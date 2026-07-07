//! Backend-neutral rule/chain model + the chained rule-hash used for
//! drift-detection resync (the `generictables` abstraction).
//!
//! Each programmed rule carries a hash in a comment; on resync Felix compares
//! the desired hashes against those found in the dataplane to detect external
//! tampering and to update incrementally. Hashing scheme reproduced from upstream
//! `felix/generictables/rules.go`:
//! - seed = SHA-224(chain name);
//! - for each rule, hash = SHA-224(previous_hash ++ rendered_rule);
//! - the 16-char base64-url (no padding) prefix of each hash is the token.
//!
//! Chaining the previous hash makes a rule's token depend on its position and on
//! every rule before it, so an insertion/removal/reorder is detected.

#![allow(dead_code)] // wired into the nftables dataplane in a later task

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha224};

/// Length of the rule-hash token (96 bits of entropy — collision-resistant, and
/// short enough for a comment).
pub const HASH_LENGTH: usize = 16;

/// A match fragment. `render` produces the canonical string used for hashing and
/// (eventually) for programming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    Protocol(String),
    DestPort(u16),
    SrcPort(u16),
    SrcIpSet(String),
    DestIpSet(String),
    InInterface(String),
    OutInterface(String),
    /// A pre-rendered raw fragment (escape hatch).
    Raw(String),
}

impl Match {
    fn render(&self) -> String {
        match self {
            Match::Protocol(p) => format!("proto {p}"),
            Match::DestPort(n) => format!("dport {n}"),
            Match::SrcPort(n) => format!("sport {n}"),
            Match::SrcIpSet(s) => format!("src-ipset {s}"),
            Match::DestIpSet(s) => format!("dst-ipset {s}"),
            Match::InInterface(s) => format!("iif {s}"),
            Match::OutInterface(s) => format!("oif {s}"),
            Match::Raw(s) => s.clone(),
        }
    }
}

/// A rule action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Return,
    Jump(String),
    Goto(String),
    Masquerade,
    Log(String),
}

impl Action {
    fn render(&self) -> String {
        match self {
            Action::Accept => "accept".into(),
            Action::Drop => "drop".into(),
            Action::Return => "return".into(),
            Action::Jump(c) => format!("jump {c}"),
            Action::Goto(c) => format!("goto {c}"),
            Action::Masquerade => "masquerade".into(),
            Action::Log(p) => format!("log prefix {p}"),
        }
    }
}

/// A single rule: match criteria + action + optional comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub matches: Vec<Match>,
    pub action: Action,
    pub comment: Option<String>,
}

impl Rule {
    /// A rule with just an action.
    pub fn new(action: Action) -> Self {
        Self {
            matches: Vec::new(),
            action,
            comment: None,
        }
    }

    /// Builder: add a match.
    pub fn with_match(mut self, m: Match) -> Self {
        self.matches.push(m);
        self
    }

    /// The canonical render used for hashing (matches then action).
    fn render_for_hash(&self) -> String {
        let mut parts: Vec<String> = self.matches.iter().map(Match::render).collect();
        parts.push(self.action.render());
        parts.join(" ")
    }
}

/// An ordered chain of rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub name: String,
    pub rules: Vec<Rule>,
}

impl Chain {
    pub fn new(name: impl Into<String>, rules: Vec<Rule>) -> Self {
        Self {
            name: name.into(),
            rules,
        }
    }

    /// Compute the chained rule-hash token for each rule (parallel to `rules`).
    pub fn rule_hashes(&self) -> Vec<String> {
        let mut hash: Vec<u8> = {
            let mut s = Sha224::new();
            s.update(self.name.as_bytes());
            s.finalize().to_vec()
        };
        let mut out = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let mut s = Sha224::new();
            s.update(&hash); // chain in the previous hash
            s.update(rule.render_for_hash().as_bytes());
            hash = s.finalize().to_vec();
            let token = URL_SAFE_NO_PAD.encode(&hash);
            out.push(token[..HASH_LENGTH].to_string());
        }
        out
    }
}

/// Which rule positions differ between the desired chain and the hashes found in
/// the dataplane. An empty result means the chain is already in sync. Positions
/// beyond `dataplane_hashes` (appended rules) and missing tail rules are both
/// reported.
pub fn drifted_positions(desired: &Chain, dataplane_hashes: &[String]) -> Vec<usize> {
    let want = desired.rule_hashes();
    let max = want.len().max(dataplane_hashes.len());
    (0..max)
        .filter(|&i| want.get(i) != dataplane_hashes.get(i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(name: &str, rules: Vec<Rule>) -> Chain {
        Chain::new(name, rules)
    }

    fn allow_from(ipset: &str, port: u16) -> Rule {
        Rule::new(Action::Accept)
            .with_match(Match::Protocol("tcp".into()))
            .with_match(Match::SrcIpSet(ipset.into()))
            .with_match(Match::DestPort(port))
    }

    #[test]
    fn hashes_are_deterministic_and_right_length() {
        let c = chain(
            "cali-fw-cali123",
            vec![allow_from("s:web", 443), Rule::new(Action::Drop)],
        );
        let h1 = c.rule_hashes();
        let h2 = c.rule_hashes();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 2);
        assert!(h1.iter().all(|h| h.len() == HASH_LENGTH));
        assert_ne!(h1[0], h1[1]);
    }

    #[test]
    fn chain_name_salts_the_hashes() {
        let rules = vec![allow_from("s:web", 443)];
        let a = chain("cali-A", rules.clone()).rule_hashes();
        let b = chain("cali-B", rules).rule_hashes();
        assert_ne!(
            a[0], b[0],
            "identical rule in different chains must hash differently"
        );
    }

    #[test]
    fn position_affects_hash() {
        let r = allow_from("s:web", 443);
        let drop = Rule::new(Action::Drop);
        let first = chain("c", vec![r.clone(), drop.clone()]).rule_hashes();
        let second = chain("c", vec![drop, r]).rule_hashes();
        // The accept rule is at position 0 in `first`, position 1 in `second`.
        assert_ne!(first[0], second[1]);
    }

    #[test]
    fn changing_a_rule_changes_it_and_all_following() {
        let base = chain(
            "c",
            vec![
                allow_from("s:web", 443),
                allow_from("s:api", 8080),
                Rule::new(Action::Drop),
            ],
        );
        let changed = chain(
            "c",
            vec![
                allow_from("s:web", 8443),
                allow_from("s:api", 8080),
                Rule::new(Action::Drop),
            ],
        );
        let hb = base.rule_hashes();
        let hc = changed.rule_hashes();
        assert_ne!(hb[0], hc[0]); // the edited rule
        assert_ne!(hb[1], hc[1]); // chained → downstream rules shift too
        assert_ne!(hb[2], hc[2]);
    }

    #[test]
    fn drift_detection() {
        let c = chain("c", vec![allow_from("s:web", 443), Rule::new(Action::Drop)]);
        let current = c.rule_hashes();
        // In sync → no drift.
        assert!(drifted_positions(&c, &current).is_empty());
        // Dataplane tampered at position 1.
        let mut tampered = current.clone();
        tampered[1] = "XXXXXXXXXXXXXXXX".to_string();
        assert_eq!(drifted_positions(&c, &tampered), vec![1]);
        // Dataplane missing the last rule (only first present).
        assert_eq!(drifted_positions(&c, &current[..1]), vec![1]);
        // Dataplane has an extra stale rule appended.
        let mut extra = current.clone();
        extra.push("stale-hash-000000".to_string());
        assert_eq!(drifted_positions(&c, &extra), vec![2]);
    }
}
