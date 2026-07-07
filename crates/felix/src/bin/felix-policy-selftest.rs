//! End-to-end policy→nftables self-test: build a Calico NetworkPolicy, render it
//! to nft, program it via `nft -f -`, verify it read back, delete. Run inside a
//! rootless netns (`unshare -rn`); driven by the integration test.

fn main() {
    if let Err(e) = run() {
        eprintln!("felix-policy-selftest FAILED: {e}");
        std::process::exit(1);
    }
    println!("felix-policy-selftest OK");
}

fn run() -> Result<(), String> {
    use apis::{Action, EntityRule, NetworkPolicySpec, PolicyType, Protocol, Rule};
    use felix::nft::{delete_table, list_ruleset};
    use felix::policy_render::render_ingress_policies;

    let spec = NetworkPolicySpec {
        selector: "app == 'db'".into(),
        types: vec![PolicyType::Ingress],
        ingress: vec![Rule {
            action: Action::Allow,
            protocol: Some(Protocol::Named("TCP".into())),
            source: EntityRule {
                nets: vec!["10.0.0.0/24".into()],
                ..Default::default()
            },
            destination: EntityRule {
                ports: vec![5432],
                ..Default::default()
            },
        }],
        ..Default::default()
    };

    let table = render_ingress_policies("inet", "calico-poltest", &[("allow-db".into(), spec)]);
    table.apply()?;

    let listed = list_ruleset()?;
    for needle in [
        "table inet calico-poltest",
        "chain cali-input",
        "chain cali-pi-allow-db",
        "jump cali-pi-allow-db",
        "tcp dport 5432", // nft canonicalizes meta l4proto tcp + th dport
        "ip saddr 10.0.0.0/24",
        "drop",
    ] {
        if !listed.contains(needle) {
            return Err(format!(
                "programmed policy missing {needle:?}; got:\n{listed}"
            ));
        }
    }

    delete_table("inet", "calico-poltest")?;
    if list_ruleset()?.contains("calico-poltest") {
        return Err("table still present after delete".into());
    }

    // --- selector-based peer → named nft set, programmed for real ---
    selector_case()?;
    Ok(())
}

fn selector_case() -> Result<(), String> {
    use apis::{Action, EntityRule, NetworkPolicySpec, PolicyType, Rule};
    use felix::nft::{delete_table, list_ruleset};
    use felix::policy_render::{render_ingress_policies_with_endpoints, Endpoint};
    use std::collections::BTreeMap;

    let spec = NetworkPolicySpec {
        selector: "app == 'db'".into(),
        types: vec![PolicyType::Ingress],
        ingress: vec![Rule {
            action: Action::Allow,
            protocol: None,
            source: EntityRule {
                selector: Some("app == 'web'".into()),
                ..Default::default()
            },
            destination: EntityRule::default(),
        }],
        ..Default::default()
    };
    let ep = |app: &str, ip: &str| Endpoint {
        labels: BTreeMap::from([("app".to_string(), app.to_string())]),
        ip: ip.to_string(),
    };
    let endpoints = vec![ep("web", "10.0.0.1"), ep("db", "10.0.0.9")];

    let table = render_ingress_policies_with_endpoints(
        "inet",
        "calico-ipsettest",
        &[("allow-web".into(), spec)],
        &endpoints,
    );
    table.apply()?;
    let listed = list_ruleset()?;
    for needle in ["set cali-s-0", "10.0.0.1", "@cali-s-0"] {
        if !listed.contains(needle) {
            return Err(format!("selector case missing {needle:?}; got:\n{listed}"));
        }
    }
    if listed.contains("10.0.0.9") {
        return Err("db endpoint should not be in the web set".into());
    }
    delete_table("inet", "calico-ipsettest")?;
    Ok(())
}
