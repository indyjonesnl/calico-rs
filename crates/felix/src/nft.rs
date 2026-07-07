//! nftables programming: render the rule model to nft syntax and apply it via
//! `nft -f -`. This is the real default-dataplane programming path (validated in
//! a rootless netns). It complements `nftables.rs` (the backend-neutral model +
//! drift-hash); here we emit concrete nft and talk to the kernel.
//!
//! Shelling to `nft` is the v1 mechanism; a netlink-native backend (rustables)
//! can replace `apply`/`list_ruleset` without changing the render model.

#![allow(dead_code)] // wired into the felix dataplane loop in a later task

use std::io::Write;
use std::process::{Command, Stdio};

/// A rule verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Return,
    Jump(String),
    Goto(String),
    /// Source NAT to the outbound interface's address (NAT postrouting).
    Masquerade,
}

impl Verdict {
    fn render(&self) -> String {
        match self {
            Verdict::Accept => "accept".into(),
            Verdict::Drop => "drop".into(),
            Verdict::Return => "return".into(),
            Verdict::Jump(c) => format!("jump {c}"),
            Verdict::Goto(c) => format!("goto {c}"),
            Verdict::Masquerade => "masquerade".into(),
        }
    }
}

/// A single nft match expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftMatch {
    /// `meta l4proto <p>` (e.g. tcp/udp).
    L4Proto(String),
    /// `th dport <n>` (transport-header destination port).
    DestPort(u16),
    /// `th sport <n>`.
    SrcPort(u16),
    /// `ip saddr <cidr>`.
    SrcAddr(String),
    /// `ip daddr <cidr>`.
    DestAddr(String),
    /// `iifname "<if>"`.
    InInterface(String),
    /// `oifname "<if>"`.
    OutInterface(String),
    /// `ip saddr @<set>` — source address in a named set (resolved selector).
    SrcSet(String),
    /// `ip daddr @<set>`.
    DestSet(String),
}

impl NftMatch {
    fn render(&self) -> String {
        match self {
            NftMatch::L4Proto(p) => format!("meta l4proto {p}"),
            NftMatch::DestPort(n) => format!("th dport {n}"),
            NftMatch::SrcPort(n) => format!("th sport {n}"),
            NftMatch::SrcAddr(c) => format!("ip saddr {c}"),
            NftMatch::DestAddr(c) => format!("ip daddr {c}"),
            NftMatch::InInterface(i) => format!("iifname \"{i}\""),
            NftMatch::OutInterface(o) => format!("oifname \"{o}\""),
            NftMatch::SrcSet(s) => format!("ip saddr @{s}"),
            NftMatch::DestSet(s) => format!("ip daddr @{s}"),
        }
    }
}

/// A named nft set (an IP set — the resolved membership of a selector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub name: String,
    /// Element addresses (bare IPs).
    pub elements: Vec<String>,
}

/// An nft rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRule {
    pub matches: Vec<NftMatch>,
    pub verdict: Verdict,
    pub comment: Option<String>,
}

impl NftRule {
    pub fn new(verdict: Verdict) -> Self {
        Self {
            matches: Vec::new(),
            verdict,
            comment: None,
        }
    }
    pub fn with(mut self, m: NftMatch) -> Self {
        self.matches.push(m);
        self
    }
    pub fn comment(mut self, c: impl Into<String>) -> Self {
        self.comment = Some(c.into());
        self
    }
    fn render(&self) -> String {
        let mut parts: Vec<String> = self.matches.iter().map(NftMatch::render).collect();
        parts.push(self.verdict.render());
        let mut line = parts.join(" ");
        if let Some(c) = &self.comment {
            line.push_str(&format!(" comment \"{c}\""));
        }
        line
    }
}

/// The nftables chain type of a base chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainType {
    /// Packet filtering (`type filter`).
    #[default]
    Filter,
    /// Network address translation (`type nat`) — masquerade/DNAT/SNAT.
    Nat,
}

impl ChainType {
    fn render(&self) -> &'static str {
        match self {
            ChainType::Filter => "filter",
            ChainType::Nat => "nat",
        }
    }
}

/// A base-chain hook (present ⇒ the chain is attached to the given hook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseHook {
    pub chain_type: ChainType,
    pub hook: String,  // input | output | forward | postrouting
    pub priority: i32, // filter = 0, srcnat = 100
    pub policy_accept: bool,
}

/// An nft chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftChain {
    pub name: String,
    pub base: Option<BaseHook>,
    pub rules: Vec<NftRule>,
}

impl NftChain {
    pub fn regular(name: impl Into<String>, rules: Vec<NftRule>) -> Self {
        Self {
            name: name.into(),
            base: None,
            rules,
        }
    }
    pub fn base(name: impl Into<String>, hook: BaseHook, rules: Vec<NftRule>) -> Self {
        Self {
            name: name.into(),
            base: Some(hook),
            rules,
        }
    }
}

/// A full table's ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftTable {
    /// Family, e.g. `inet`.
    pub family: String,
    pub name: String,
    pub sets: Vec<NftSet>,
    pub chains: Vec<NftChain>,
}

impl NftTable {
    pub fn new(family: impl Into<String>, name: impl Into<String>, chains: Vec<NftChain>) -> Self {
        Self {
            family: family.into(),
            name: name.into(),
            sets: Vec::new(),
            chains,
        }
    }

    /// Builder: attach named sets (resolved IP sets) to the table.
    pub fn with_sets(mut self, sets: Vec<NftSet>) -> Self {
        self.sets = sets;
        self
    }

    /// Render the table to nft syntax (an `nft -f -` document). Flushes the table
    /// first so the render is idempotent (declarative replace).
    pub fn render(&self) -> String {
        let mut out = String::new();
        // `add` then `flush` makes re-applying the same document idempotent.
        out.push_str(&format!("add table {} {}\n", self.family, self.name));
        out.push_str(&format!("flush table {} {}\n", self.family, self.name));
        out.push_str(&format!("table {} {} {{\n", self.family, self.name));
        for set in &self.sets {
            out.push_str(&format!("  set {} {{\n    type ipv4_addr\n", set.name));
            if !set.elements.is_empty() {
                out.push_str(&format!(
                    "    elements = {{ {} }}\n",
                    set.elements.join(", ")
                ));
            }
            out.push_str("  }\n");
        }
        for chain in &self.chains {
            out.push_str(&format!("  chain {} {{\n", chain.name));
            if let Some(b) = &chain.base {
                let pol = if b.policy_accept { "accept" } else { "drop" };
                out.push_str(&format!(
                    "    type {} hook {} priority {}; policy {};\n",
                    b.chain_type.render(),
                    b.hook,
                    b.priority,
                    pol
                ));
            }
            for rule in &chain.rules {
                out.push_str(&format!("    {}\n", rule.render()));
            }
            out.push_str("  }\n");
        }
        out.push_str("}\n");
        out
    }

    /// Apply this table via `nft -f -`.
    pub fn apply(&self) -> Result<(), String> {
        apply_ruleset(&self.render())
    }
}

/// Feed a ruleset document to `nft -f -`.
pub fn apply_ruleset(doc: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nft: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(doc.as_bytes())
        .map_err(|e| format!("write nft: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft wait: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Return the current ruleset (`nft list ruleset`).
pub fn list_ruleset() -> Result<String, String> {
    let out = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .map_err(|e| format!("run nft list: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "nft list failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Delete a table (`delete table <family> <name>`), ignoring "not found".
pub fn delete_table(family: &str, name: &str) -> Result<(), String> {
    let out = Command::new("nft")
        .args(["delete", "table", family, name])
        .output()
        .map_err(|e| format!("run nft delete: {e}"))?;
    if out.status.success() || String::from_utf8_lossy(&out.stderr).contains("No such file") {
        Ok(())
    } else {
        Err(format!(
            "nft delete failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_nft_document() {
        let t = NftTable::new(
            "inet",
            "calico",
            vec![NftChain::base(
                "input",
                BaseHook {
                    chain_type: ChainType::Filter,
                    hook: "input".into(),
                    priority: 0,
                    policy_accept: true,
                },
                vec![
                    NftRule::new(Verdict::Accept)
                        .with(NftMatch::L4Proto("tcp".into()))
                        .with(NftMatch::DestPort(443))
                        .with(NftMatch::SrcAddr("10.0.0.0/24".into()))
                        .comment("allow-web"),
                    NftRule::new(Verdict::Drop),
                ],
            )],
        );
        let doc = t.render();
        assert!(doc.contains("flush table inet calico"));
        assert!(doc.contains("type filter hook input priority 0; policy accept;"));
        assert!(doc.contains("th dport 443 ip saddr 10.0.0.0/24 accept comment \"allow-web\""));
        assert!(doc.trim_end().ends_with('}'));
    }

    #[test]
    fn verdicts_and_matches_render() {
        assert_eq!(Verdict::Jump("cali-fw".into()).render(), "jump cali-fw");
        assert_eq!(
            NftMatch::InInterface("cali123".into()).render(),
            "iifname \"cali123\""
        );
        assert_eq!(
            NftMatch::SrcAddr("1.2.3.0/24".into()).render(),
            "ip saddr 1.2.3.0/24"
        );
    }
}
