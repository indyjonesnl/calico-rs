//! NAT-outgoing (masquerade). Pods on a pool with `natOutgoing: true` reach
//! destinations *outside* the cluster's pod address space with their source
//! rewritten to the node's address; pod-to-pod traffic (any pool → any pool) is
//! left un-NAT'd so pods see each other's real addresses.
//!
//! Programmed as an nftables `nat` table with a `postrouting` base chain. For
//! each (natOutgoing pool `s`, any pool `d`) an `ip saddr s ip daddr d return`
//! rule, then for each natOutgoing pool `s` an `ip saddr s masquerade` rule. The
//! RETURN rules precede the masquerade so intra-cluster traffic is exempt. This
//! mirrors upstream Calico's `cali-nat-outgoing` postrouting logic.

use datastore::{KddBackend, ResourceKind};

use crate::nft::{BaseHook, ChainType, NftChain, NftMatch, NftRule, NftTable, Verdict};

pub const TABLE: &str = "calico-nat";
/// nftables `srcnat` priority (100) for the postrouting hook.
const SRCNAT_PRIORITY: i32 = 100;

/// Build the NAT-outgoing table from the set of natOutgoing pool CIDRs and the
/// set of *all* pool CIDRs (the intra-cluster exemption). IPv4 only for now.
pub fn build_nat_table(nat_out_pools: &[String], all_pools: &[String]) -> NftTable {
    let mut rules: Vec<NftRule> = Vec::new();

    // Exempt intra-cluster traffic (pod → any pool) from masquerade.
    for s in nat_out_pools {
        for d in all_pools {
            rules.push(
                NftRule::new(Verdict::Return)
                    .with(NftMatch::SrcAddr(s.clone()))
                    .with(NftMatch::DestAddr(d.clone())),
            );
        }
    }
    // Masquerade the remainder (pod → external).
    for s in nat_out_pools {
        rules.push(
            NftRule::new(Verdict::Masquerade)
                .with(NftMatch::SrcAddr(s.clone()))
                .comment("cali-nat-outgoing"),
        );
    }

    let postrouting = NftChain::base(
        "cali-postrouting",
        BaseHook {
            chain_type: ChainType::Nat,
            hook: "postrouting".into(),
            priority: SRCNAT_PRIORITY,
            policy_accept: true,
        },
        rules,
    );
    NftTable::new("ip", TABLE, vec![postrouting])
}

/// Build the desired NAT-outgoing table document from the current IP pools.
pub async fn desired_doc(backend: &KddBackend) -> Result<String, String> {
    let pools = backend
        .list(ResourceKind::IpPool, None)
        .await
        .map_err(|e| e.to_string())?;

    let mut all_pools = Vec::new();
    let mut nat_out_pools = Vec::new();
    for p in &pools {
        let disabled = p
            .spec
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if disabled {
            continue;
        }
        let Some(cidr) = p.spec.get("cidr").and_then(|v| v.as_str()) else {
            continue;
        };
        // IPv4 only for now.
        if cidr.contains(':') {
            continue;
        }
        all_pools.push(cidr.to_string());
        if p.spec
            .get("natOutgoing")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            nat_out_pools.push(cidr.to_string());
        }
    }

    Ok(build_nat_table(&nat_out_pools, &all_pools).render())
}

/// One reconcile pass: read the IP pools, build the NAT-outgoing table, apply it.
pub async fn reconcile_once(backend: &KddBackend) -> Result<(), String> {
    crate::nft::apply_ruleset(&desired_doc(backend).await?)
}

/// Run the NAT reconcile loop, polling on `interval`. The rendered ruleset is
/// applied only when it *changes* — re-applying flushes the table, and removing
/// a `masquerade` rule makes the kernel purge masqueraded conntrack entries,
/// which would tear down every established pod→external connection (long-lived
/// watches especially) each cycle. Since pools rarely change, this is a no-op
/// after the first apply.
pub async fn run(backend: KddBackend, interval: std::time::Duration) {
    let mut applied: Option<String> = None;
    loop {
        match desired_doc(&backend).await {
            Ok(doc) if applied.as_deref() != Some(doc.as_str()) => {
                match crate::nft::apply_ruleset(&doc) {
                    Ok(()) => applied = Some(doc),
                    Err(e) => eprintln!("nat reconcile failed: {e}"),
                }
            }
            Ok(_) => {} // unchanged — do not re-flush
            Err(e) => eprintln!("nat reconcile failed: {e}"),
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_return_before_masquerade() {
        let doc = build_nat_table(
            &["192.168.0.0/16".to_string()],
            &["192.168.0.0/16".to_string()],
        )
        .render();
        assert!(doc.contains("type nat hook postrouting priority 100"));
        // Intra-cluster exemption precedes the masquerade.
        let ret = doc.find("ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 return");
        let masq = doc.find("ip saddr 192.168.0.0/16 masquerade");
        assert!(ret.is_some() && masq.is_some());
        assert!(ret.unwrap() < masq.unwrap());
    }

    #[test]
    fn no_masquerade_when_no_natoutgoing_pools() {
        let doc = build_nat_table(&[], &["192.168.0.0/16".to_string()]).render();
        assert!(!doc.contains("masquerade"));
        assert!(doc.contains("type nat hook postrouting"));
    }
}
