//! Self-test: program a Calico-style nftables table and verify it, in the
//! current network namespace. Run inside a rootless netns (`unshare -rn`);
//! driven by the integration test. Exits 0 on success.

fn main() {
    if let Err(e) = run() {
        eprintln!("felix-nft-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-nft-selftest OK");
}

fn run() -> Result<(), String> {
    use felix::nft::*;

    let table = NftTable::new(
        "inet",
        "calico-selftest",
        vec![
            NftChain::base(
                "input",
                BaseHook {
                    chain_type: ChainType::Filter,
                    hook: "input".into(),
                    priority: 0,
                    policy_accept: true,
                },
                vec![NftRule::new(Verdict::Jump("cali-fw".into()))],
            ),
            NftChain::regular(
                "cali-fw",
                vec![
                    NftRule::new(Verdict::Accept)
                        .with(NftMatch::L4Proto("tcp".into()))
                        .with(NftMatch::DestPort(443))
                        .with(NftMatch::SrcAddr("10.0.0.0/24".into()))
                        .comment("allow-web"),
                    NftRule::new(Verdict::Drop).comment("default-deny"),
                ],
            ),
        ],
    );

    // Apply, then read it back.
    table.apply()?;
    let listed = list_ruleset()?;
    // nft canonicalizes `meta l4proto tcp th dport 443` → `tcp dport 443`.
    for needle in [
        "table inet calico-selftest",
        "chain cali-fw",
        "tcp dport 443",
        "ip saddr 10.0.0.0/24 accept",
        "jump cali-fw",
    ] {
        if !listed.contains(needle) {
            return Err(format!(
                "programmed ruleset missing {needle:?}; got:\n{listed}"
            ));
        }
    }

    // Re-apply is idempotent (flush+add), then clean up.
    table.apply()?;
    delete_table("inet", "calico-selftest")?;
    if list_ruleset()?.contains("calico-selftest") {
        return Err("table still present after delete".into());
    }
    Ok(())
}
