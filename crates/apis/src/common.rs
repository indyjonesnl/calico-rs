//! Shared metadata used by all resources.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A trimmed-down Kubernetes object metadata: the fields Calico logic actually
/// reads. (The full CRD wrapper — apiVersion/kind/status — is added at the
/// `kube::CustomResource` layer.)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl Metadata {
    /// Convenience constructor for a cluster-scoped (non-namespaced) object.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}
