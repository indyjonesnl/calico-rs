//! CRD manifest generation from the derived resource types.
//!
//! Each `#[derive(CustomResource)]` type exposes `::crd()` (via
//! [`kube::CustomResourceExt`]) which builds the `CustomResourceDefinition` from
//! the type's JsonSchema. This module collects the implemented kinds and renders
//! them as a multi-document YAML manifest to apply to a cluster (see the
//! `gen-crds` binary), making the `apis` types the authoritative schema.

use kube::CustomResourceExt;

/// Render all implemented CRDs as a multi-document YAML manifest.
pub fn crd_yaml() -> String {
    // Extend this list as more `CustomResource` types are added (T013 rollout).
    let docs = [
        crate::IPPool::crd(),
        crate::NetworkPolicy::crd(),
        crate::GlobalNetworkPolicy::crd(),
        crate::Tier::crd(),
        crate::Profile::crd(),
        crate::ClusterInformation::crd(),
        crate::IPAMBlock::crd(),
        crate::BlockAffinity::crd(),
        crate::IPAMHandle::crd(),
        crate::IPAMConfiguration::crd(),
        crate::HostEndpoint::crd(),
        crate::NetworkSet::crd(),
        crate::GlobalNetworkSet::crd(),
        crate::BGPConfiguration::crd(),
        crate::BGPPeer::crd(),
        crate::FelixConfiguration::crd(),
        crate::StagedNetworkPolicy::crd(),
        crate::StagedGlobalNetworkPolicy::crd(),
        crate::StagedKubernetesNetworkPolicy::crd(),
        crate::BGPFilter::crd(),
        crate::KubeControllersConfiguration::crd(),
        crate::CalicoNodeStatus::crd(),
    ];
    docs.iter()
        .map(|c| serde_yaml_ng::to_string(c).expect("CRD serializes to YAML"))
        .collect::<Vec<_>>()
        .join("---\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ippool_crd_generates_expected_metadata() {
        let crd = crate::IPPool::crd();
        assert_eq!(crd.spec.group, "crd.projectcalico.org");
        assert_eq!(crd.spec.names.kind, "IPPool");
        assert_eq!(crd.spec.names.plural, "ippools");
        assert_eq!(crd.spec.scope, "Cluster");
        // The stored version is v1.
        assert!(crd
            .spec
            .versions
            .iter()
            .any(|v| v.name == "v1" && v.storage));
    }

    #[test]
    fn namespaced_and_cluster_scopes() {
        assert_eq!(crate::NetworkPolicy::crd().spec.scope, "Namespaced");
        assert_eq!(crate::GlobalNetworkPolicy::crd().spec.scope, "Cluster");
        assert_eq!(crate::ClusterInformation::crd().spec.scope, "Cluster");
        assert_eq!(crate::StagedNetworkPolicy::crd().spec.scope, "Namespaced");
        assert_eq!(
            crate::StagedGlobalNetworkPolicy::crd().spec.scope,
            "Cluster"
        );
        assert_eq!(
            crate::StagedKubernetesNetworkPolicy::crd().spec.scope,
            "Namespaced"
        );
        assert_eq!(crate::BGPFilter::crd().spec.scope, "Cluster");
        assert_eq!(
            crate::KubeControllersConfiguration::crd().spec.scope,
            "Cluster"
        );
        assert_eq!(crate::CalicoNodeStatus::crd().spec.scope, "Cluster");
    }

    #[test]
    fn crd_yaml_is_applyable() {
        let yaml = crd_yaml();
        assert!(yaml.contains("kind: CustomResourceDefinition"));
        assert!(yaml.contains("name: ippools.crd.projectcalico.org"));
        assert!(yaml.contains("name: networkpolicies.crd.projectcalico.org"));
        assert!(yaml.contains("name: globalnetworkpolicies.crd.projectcalico.org"));
        // The generated OpenAPI schema carries our camelCase spec fields.
        assert!(yaml.contains("vxlanMode"));
        assert!(yaml.contains("natOutgoing"));
    }

    #[test]
    fn new_p2_kinds_are_registered() {
        let yaml = crd_yaml();
        assert!(yaml.contains("name: stagednetworkpolicies.crd.projectcalico.org"));
        assert!(yaml.contains("name: stagedglobalnetworkpolicies.crd.projectcalico.org"));
        assert!(yaml.contains("name: stagedkubernetesnetworkpolicies.crd.projectcalico.org"));
        assert!(yaml.contains("name: bgpfilters.crd.projectcalico.org"));
        assert!(yaml.contains("name: kubecontrollersconfigurations.crd.projectcalico.org"));
        assert!(yaml.contains("name: caliconodestatuses.crd.projectcalico.org"));
        assert!(yaml.contains("stagedAction"));
    }
}
