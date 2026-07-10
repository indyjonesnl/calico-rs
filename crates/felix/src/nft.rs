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

/// The "accept" mark bit — Calico felix's `MarkAccept` (here a fixed bit; upstream's
/// is config-driven). This bit is the crux of correct forward-path policy semantics.
///
/// A forwarded pod→pod packet is steered by `cali-forward` through BOTH direction
/// chains — `iifname <src> jump cali-fw-<src>` (source egress) AND
/// `oifname <dst> jump cali-tw-<dst>` (dest ingress). If an ALLOW rendered as a
/// terminal `accept`, the first direction to allow would end the whole traversal and
/// the other direction's policy would never be evaluated. So an ALLOW instead SETs
/// this bit and `return`s (non-terminal, [`Verdict::SetAcceptMarkReturn`]); a DENY is
/// the only terminal verdict (`drop`). A packet is truly accepted only via
/// `cali-forward`'s fall-through, after surviving (being `return`ed by) every
/// applicable direction chain. Each dispatch chain [`Verdict::ClearAcceptMark`]s the
/// bit on entry so a mark left set by the other direction's chain cannot leak in.
pub const ACCEPT_MARK: u32 = 0x0100_0000;

/// A rule verdict (the trailing statement of an nft rule). Most are true verdicts;
/// [`Verdict::SetAcceptMarkReturn`] is a mark-set + `return` compound and
/// [`Verdict::ClearAcceptMark`] is a bare mangle statement (no verdict → the packet
/// falls through to the next rule) — both encode the accept-mark policy semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Return,
    Jump(String),
    Goto(String),
    /// Source NAT to the outbound interface's address (NAT postrouting).
    Masquerade,
    /// Calico's non-terminal ALLOW: set the [`ACCEPT_MARK`] bit, then `return` to the
    /// calling (dispatch) chain — so the OTHER direction's chain still runs. Renders
    /// `meta mark set meta mark or 0x01000000 return`.
    SetAcceptMarkReturn,
    /// Clear the [`ACCEPT_MARK`] bit (a mangle statement with no verdict, so control
    /// falls through to the next rule). Emitted at a dispatch chain's entry so a mark
    /// set while the same packet traversed the other direction's chain cannot cause a
    /// premature return here. Renders `meta mark set meta mark and 0xfeffffff`.
    ClearAcceptMark,
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
            Verdict::SetAcceptMarkReturn => {
                format!("meta mark set meta mark or 0x{ACCEPT_MARK:08x} return")
            }
            Verdict::ClearAcceptMark => {
                format!("meta mark set meta mark and 0x{:08x}", !ACCEPT_MARK)
            }
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
    /// `meta mark & <ACCEPT_MARK> == <ACCEPT_MARK>` — the [`ACCEPT_MARK`] bit is set,
    /// i.e. a policy/profile chain jumped so far in this direction ALLOWed. A
    /// dispatch chain uses this to `return` as soon as one direction allows.
    AcceptMarkSet,
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
            NftMatch::AcceptMarkSet => {
                format!("meta mark & 0x{ACCEPT_MARK:08x} == 0x{ACCEPT_MARK:08x}")
            }
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
    pub(crate) fn render(&self) -> String {
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
    /// The base-chain declaration body (`type … hook … priority …; policy …;`) for
    /// an `add chain` statement, or `None` for a regular chain.
    pub(crate) fn base_decl(&self) -> Option<String> {
        self.base.as_ref().map(|b| {
            let pol = if b.policy_accept { "accept" } else { "drop" };
            format!(
                "type {} hook {} priority {}; policy {};",
                b.chain_type.render(),
                b.hook,
                b.priority,
                pol
            )
        })
    }

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

/// Render a **non-destructive** per-chain update document for `nft -f -`.
///
/// This is the apply path for managers (policy/endpoint chains) that share the
/// `inet calico` table with the [`crate::ipset_manager`]'s named sets. It NEVER
/// flushes the table or the ruleset — doing so would wipe those sets (which are
/// table-scoped). Instead each desired chain is flushed and re-filled in place,
/// and no-longer-desired chains are deleted, leaving sets and untouched chains
/// intact.
///
/// The statement order is chosen so a single atomic `nft -f -` transaction always
/// applies cleanly:
/// 1. `add table` (idempotent — no flush).
/// 2. `add chain` for every desired chain (idempotent; base chains carry their
///    hook decl) — so every `jump`/`goto` target exists before any rule is added.
/// 3. `flush chain` for every desired chain (clear stale rules) and for every
///    chain about to be deleted (so it is empty and unreferenced).
/// 4. `add rule` for every desired chain's rules (all jump targets now resolve).
/// 5. `delete chain` for no-longer-desired chains (now empty and unreferenced).
pub fn render_chain_updates(
    family: &str,
    table: &str,
    chains: &[NftChain],
    deletions: &[String],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("add table {family} {table}\n"));
    // 2. Ensure every desired chain exists (create-if-absent; idempotent).
    for c in chains {
        match c.base_decl() {
            Some(decl) => out.push_str(&format!(
                "add chain {family} {table} {} {{ {decl} }}\n",
                c.name
            )),
            None => out.push_str(&format!("add chain {family} {table} {}\n", c.name)),
        }
    }
    // 3. Flush desired chains, then chains to be removed.
    for c in chains {
        out.push_str(&format!("flush chain {family} {table} {}\n", c.name));
    }
    for name in deletions {
        out.push_str(&format!("flush chain {family} {table} {name}\n"));
    }
    // 4. Re-add rules for desired chains.
    for c in chains {
        for r in &c.rules {
            out.push_str(&format!(
                "add rule {family} {table} {} {}\n",
                c.name,
                r.render()
            ));
        }
    }
    // 5. Delete no-longer-desired chains (empty + unreferenced by now).
    for name in deletions {
        out.push_str(&format!("delete chain {family} {table} {name}\n"));
    }
    out
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
    fn chain_updates_are_non_destructive_and_ordered() {
        // A base chain that jumps to a regular chain which references a named set.
        let base = NftChain::base(
            "cali-forward",
            BaseHook {
                chain_type: ChainType::Filter,
                hook: "forward".into(),
                priority: 0,
                policy_accept: true,
            },
            vec![NftRule::new(Verdict::Jump("cali-tw-cali123".into()))
                .with(NftMatch::OutInterface("cali123".into()))],
        );
        let tw = NftChain::regular(
            "cali-tw-cali123",
            vec![
                NftRule::new(Verdict::Jump("cali-pi-default-allow".into())),
                NftRule::new(Verdict::Drop).comment("default deny"),
            ],
        );
        let pol = NftChain::regular(
            "cali-pi-default-allow",
            vec![NftRule::new(Verdict::Accept).with(NftMatch::SrcSet("cali40abc".into()))],
        );
        let doc = render_chain_updates(
            "inet",
            "calico",
            &[base, tw, pol],
            &["cali-pi-default-stale".to_string()],
        );

        // NEVER flush the table or the whole ruleset (that would wipe the sets).
        assert!(!doc.contains("flush table"), "must not flush the table");
        assert!(!doc.contains("flush ruleset"), "must not flush the ruleset");
        // Idempotent table creation, per-chain flush + re-add.
        assert!(doc.contains("add table inet calico"));
        assert!(doc.contains(
            "add chain inet calico cali-forward { type filter hook forward priority 0; policy accept; }"
        ));
        assert!(doc.contains("add chain inet calico cali-tw-cali123"));
        assert!(doc.contains("flush chain inet calico cali-tw-cali123"));
        assert!(doc.contains("add rule inet calico cali-tw-cali123 jump cali-pi-default-allow"));
        assert!(
            doc.contains("add rule inet calico cali-pi-default-allow ip saddr @cali40abc accept")
        );
        assert!(doc.contains(
            "add rule inet calico cali-forward oifname \"cali123\" jump cali-tw-cali123"
        ));
        // Stale chain flushed then deleted (no table wipe).
        assert!(doc.contains("flush chain inet calico cali-pi-default-stale"));
        assert!(doc.contains("delete chain inet calico cali-pi-default-stale"));

        // Ordering: every `add chain` precedes every `add rule` (so jumps resolve),
        // and `delete chain` comes last (after the referencing rules are gone).
        let first_add_rule = doc.find("add rule").unwrap();
        let last_add_chain = doc.rfind("add chain").unwrap();
        assert!(
            last_add_chain < first_add_rule,
            "all chains created before rules"
        );
        let delete_pos = doc.find("delete chain").unwrap();
        assert!(
            delete_pos > first_add_rule,
            "chains deleted after rules re-added"
        );
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

    #[test]
    fn accept_mark_verdicts_and_match_render() {
        // ALLOW is non-terminal: set the mark then return (NOT a bare `accept`).
        assert_eq!(
            Verdict::SetAcceptMarkReturn.render(),
            "meta mark set meta mark or 0x01000000 return"
        );
        // Entry clear uses the complement mask and has no verdict (falls through).
        assert_eq!(
            Verdict::ClearAcceptMark.render(),
            "meta mark set meta mark and 0xfeffffff"
        );
        // The "did a chain allow?" test.
        assert_eq!(
            NftMatch::AcceptMarkSet.render(),
            "meta mark & 0x01000000 == 0x01000000"
        );
        // A return-if-accepted rule composes the match with a plain return.
        let rule = NftRule::new(Verdict::Return).with(NftMatch::AcceptMarkSet);
        assert_eq!(rule.render(), "meta mark & 0x01000000 == 0x01000000 return");
    }
}
