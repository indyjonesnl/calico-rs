//! Pure IP-set rendering helpers for the unified policy dataplane.
//!
//! These functions materialize a calc-graph IP set as an nftables **named set**
//! (the ipset equivalent) living in the shared policy table [`TABLE_FAMILY`]
//! `inet` / [`TABLE_NAME`] `calico`. They carry NO dataplane state and program
//! nothing themselves — the single table-owning [`crate::policy_table::PolicyTableManager`]
//! renders the whole `inet calico` table (sets + chains) in one atomic,
//! self-healing `nft -f -` document and calls these to emit the set portion.
//!
//! ## History (why this used to be a manager)
//!
//! This module previously hosted an `IpSetManager` — one of *two* separate
//! `InternalDataplane` managers, each applying incremental `add/delete` deltas in
//! its own `nft -f` transaction while tracking only what it had itself programmed.
//! That delta design poisoned its own transactions on agent restart / churn (a
//! stale `delete set` for state the kernel had but the fresh in-memory view did
//! not; cross-manager `@set` ordering races). It was replaced by the unified
//! full-render [`crate::policy_table`] manager, which needs only the *pure*
//! rendering below.
//!
//! ## IpSetKind → nft set type
//!
//! - [`IpSetKind::Ip`]   → `type ipv4_addr` — bare addresses (`hash:ip`).
//! - [`IpSetKind::Net`]  → `type ipv4_addr; flags interval` — CIDRs (`hash:net`).
//! - [`IpSetKind::IpAndPort`] → `type ipv4_addr . inet_service` — the concatenated
//!   named-port encoding (`hash:ip,port`); members are programmed verbatim
//!   (the calc graph emits `ADDR . PORT` element syntax).
//!
//! IPv4 first; an `ipv6_addr` set under a distinct name is a documented follow-up.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use proto::IpSetKind;
use sha2::{Digest, Sha256};

/// Family of the nft table the named sets live in (shared with the policy chains).
pub const TABLE_FAMILY: &str = "inet";
/// Name of the nft table the named sets live in (shared with the policy chains).
pub const TABLE_NAME: &str = "calico";

/// Derive the deterministic, nft-safe named-set name for an IP-set id.
///
/// The policy/endpoint rendering references sets by this exact mapping, so it must
/// depend only on the id (never on kind or membership). The token is the URL-safe
/// base64 (no padding) of the first 12 bytes of SHA-256(id) — 16 chars, 96 bits,
/// collision-resistant — behind a `cali40` prefix (echoing upstream's IPv4-set
/// naming). base64url uses only `[A-Za-z0-9_-]`, all valid in nft identifiers.
pub fn set_name_for(ip_set_id: &str) -> String {
    let digest = Sha256::digest(ip_set_id.as_bytes());
    let token = URL_SAFE_NO_PAD.encode(&digest[..12]);
    format!("cali40{token}")
}

/// The nft `type ...` (and optional `flags`) declaration for an [`IpSetKind`].
pub(crate) fn set_type_decl(kind: IpSetKind) -> &'static str {
    match kind {
        IpSetKind::Ip => "type ipv4_addr",
        IpSetKind::Net => "type ipv4_addr; flags interval",
        IpSetKind::IpAndPort => "type ipv4_addr . inet_service",
    }
}

/// Render the nft statements that declare one named set (and, if non-empty, its
/// elements) into `out`, for inclusion in the full-table document. The set
/// CONTAINER is *always* declared — even with zero members — so a policy chain's
/// `ip saddr @<set>` reference resolves (the empty-but-referenced-set case).
///
/// `members` is any deterministically-ordered iterable (the caller uses a
/// `BTreeSet`), so re-rendering the same desired state yields a byte-identical
/// document (drives the skip-if-unchanged guard).
pub(crate) fn render_set<'a>(
    out: &mut String,
    id: &str,
    kind: IpSetKind,
    members: impl Iterator<Item = &'a str>,
) {
    let name = set_name_for(id);
    out.push_str(&format!(
        "add set {TABLE_FAMILY} {TABLE_NAME} {name} {{ {}; }}\n",
        set_type_decl(kind)
    ));
    let elems: Vec<&str> = members.collect();
    if !elems.is_empty() {
        out.push_str(&format!(
            "add element {TABLE_FAMILY} {TABLE_NAME} {name} {{ {} }}\n",
            elems.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_name_is_deterministic_nft_safe_and_id_only() {
        let a = set_name_for("s:selector-foo");
        assert_eq!(a, set_name_for("s:selector-foo"), "deterministic");
        assert_ne!(a, set_name_for("s:selector-bar"), "distinct ids differ");
        assert!(a.starts_with("cali40"));
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "nft-safe identifier: {a}"
        );
    }

    #[test]
    fn kind_maps_to_nft_type() {
        assert_eq!(set_type_decl(IpSetKind::Ip), "type ipv4_addr");
        assert_eq!(
            set_type_decl(IpSetKind::Net),
            "type ipv4_addr; flags interval"
        );
        assert_eq!(
            set_type_decl(IpSetKind::IpAndPort),
            "type ipv4_addr . inet_service"
        );
    }

    #[test]
    fn empty_set_still_renders_the_container() {
        // Bug 1 regression, now inherent to the full render: a DESIRED set with
        // ZERO members must still declare its container so `@<set>` refs resolve.
        let mut out = String::new();
        render_set(&mut out, "empty1", IpSetKind::Ip, std::iter::empty());
        let name = set_name_for("empty1");
        assert!(
            out.contains(&format!(
                "add set {TABLE_FAMILY} {TABLE_NAME} {name} {{ type ipv4_addr; }}"
            )),
            "empty-but-desired set must still emit `add set`: {out}"
        );
        assert!(
            !out.contains("add element"),
            "no elements line for an empty set: {out}"
        );
    }

    #[test]
    fn net_kind_declares_interval_flag_and_elements() {
        let mut out = String::new();
        render_set(
            &mut out,
            "net1",
            IpSetKind::Net,
            ["10.0.0.0/24"].into_iter(),
        );
        assert!(out.contains("type ipv4_addr; flags interval"));
        assert!(out.contains("10.0.0.0/24"));
    }
}
