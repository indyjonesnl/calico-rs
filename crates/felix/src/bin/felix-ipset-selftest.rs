//! Self-test: drive the felix `IpSetManager` against *real* nftables named sets
//! in the current network namespace. Run inside a rootless netns
//! (`unshare --user --map-root-user --net`); the integration test
//! (`tests/ipset_netns.rs`) drives it. Exits 0 on success, non-zero on failure.
//!
//! It: programs a `hash:ip` set with two members via the manager, reads it back
//! with `nft list ruleset`, applies a delta (add one, remove one) and verifies
//! only the diff took effect, re-applies (idempotent no-op), then removes the set
//! and verifies it is gone — proving the real `nft add/delete element` delta path.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("felix-ipset-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-ipset-selftest OK");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use felix::dataplane::Manager;
    use felix::ipset_manager::{set_name_for, IpSetManager};
    use felix::nft::list_ruleset;
    use proto::{IpSetDeltaUpdate, IpSetKind, IpSetUpdate, ToDataplane};

    let id = "s:selftest";
    let name = set_name_for(id);
    let mut mgr = IpSetManager::with_nft();

    // Program a set with two members.
    mgr.on_update(&ToDataplane::IpSetUpdate(IpSetUpdate {
        id: id.into(),
        kind: IpSetKind::Ip,
        members: vec!["10.0.0.1".into(), "10.0.0.2".into()],
    }));
    mgr.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    let listed = list_ruleset()?;
    for needle in [name.as_str(), "10.0.0.1", "10.0.0.2"] {
        if !listed.contains(needle) {
            return Err(format!(
                "set missing {needle:?} after program; got:\n{listed}"
            ));
        }
    }

    // Idempotent re-apply: empty delta ⇒ no-op (must not error).
    mgr.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    // Delta: add .3, remove .1.
    mgr.on_update(&ToDataplane::IpSetDeltaUpdate(IpSetDeltaUpdate {
        id: id.into(),
        added_members: vec!["10.0.0.3".into()],
        removed_members: vec!["10.0.0.1".into()],
    }));
    mgr.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;

    let listed = list_ruleset()?;
    if !listed.contains("10.0.0.3") {
        return Err(format!("delta add 10.0.0.3 missing; got:\n{listed}"));
    }
    if !listed.contains("10.0.0.2") {
        return Err(format!("untouched 10.0.0.2 vanished; got:\n{listed}"));
    }
    // Ensure .1 was actually removed from *this* set (scope to the set block).
    if set_contains_member(&listed, &name, "10.0.0.1") {
        return Err(format!(
            "delta remove 10.0.0.1 still present; got:\n{listed}"
        ));
    }

    // Remove the set entirely and verify it is gone.
    mgr.on_update(&ToDataplane::IpSetRemove(id.into()));
    mgr.complete_deferred_work()
        .await
        .map_err(|e| e.to_string())?;
    if list_ruleset()?.contains(&name) {
        return Err("set still present after remove".into());
    }

    Ok(())
}

/// Whether `member` appears inside the `set <name> { ... }` block of an
/// `nft list ruleset` dump (avoids matching a same address in another set).
#[cfg(target_os = "linux")]
fn set_contains_member(listed: &str, name: &str, member: &str) -> bool {
    let Some(start) = listed.find(&format!("set {name} ")) else {
        return false;
    };
    let rest = &listed[start..];
    let end = rest.find('}').map(|e| e + 1).unwrap_or(rest.len());
    rest[..end].contains(member)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("felix-ipset-selftest only runs on Linux");
    std::process::exit(2);
}
