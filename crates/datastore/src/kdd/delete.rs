//! Soft-then-hard delete + hashed-hostname label helper for the KDD backend.
//!
//! Kubernetes has no compare-and-delete: a reader could race a fresh writer
//! between reading a resourceVersion and issuing `DELETE`. Calico's KDD
//! backend closes that race with a two-step **soft-then-hard delete**: mark
//! the object `deleted: true` via a CAS `update` (the linearization point —
//! once this succeeds, the delete has logically "happened"), then hard-delete
//! it gated on the *new* (resourceVersion, UID) pair. Readers are expected to
//! filter out `deleted: true` objects. Mirrors upstream
//! `libcalico-go/lib/backend/k8s/resources/ipam_affinity_v1.go` `DeleteKVP`.
//!
//! Kubernetes label values are capped at 63 characters and label selectors
//! can't do prefix/path matching, so host-scoped lookups (e.g. "all
//! BlockAffinities for host X") use a label carrying a hash of the hostname
//! instead of a path segment. Mirrors upstream
//! `libcalico-go/lib/backend/model/block_affinity.go`.

use data_encoding::BASE32_NOPAD;
use kube::api::{DeleteParams, ListParams, PostParams, Preconditions};
use serde_json::json;
use sha3::{Digest, Sha3_256};

use crate::cas::CasError;
use crate::model::ResourceKind;

use super::{map_err, to_value, KddBackend, KddValue, Op};

/// Label carrying a hash of the hostname, for host-scoped list queries
/// (upstream: `projectcalico.org/hostname-hash`).
pub const LABEL_HOSTNAME_HASH: &str = "projectcalico.org/hostname-hash";

/// Hash a hostname for [`LABEL_HOSTNAME_HASH`]: SHA3-256 of the UTF-8 bytes,
/// base32-encoded (RFC 4648 standard alphabet, no padding). Must reproduce
/// upstream `libcalico-go/lib/backend/model/block_affinity.go` byte for byte
/// (`sha3.Sum256` + `base32.StdEncoding.WithPadding(base32.NoPadding)`) — a
/// 32-byte digest base32-encodes to 52 chars, well under the 63-char label
/// value limit.
pub fn hash_hostname_for_label(hostname: &str) -> String {
    let digest = Sha3_256::digest(hostname.as_bytes());
    BASE32_NOPAD.encode(&digest)
}

/// Build the `(key, value)` label pair for `host`, for writers stamping
/// host-scoped resources (e.g. IPAM affinity creation) so
/// [`KddBackend::list_by_host`] can find them.
pub fn hostname_hash_label(host: &str) -> (String, String) {
    (
        LABEL_HOSTNAME_HASH.to_string(),
        hash_hostname_for_label(host),
    )
}

impl KddBackend {
    /// Soft-then-hard delete: mark `deleted: true` via a CAS update (the
    /// linearization point), then hard-delete gated on the new
    /// (resourceVersion, UID). Idempotent: a missing object — before the soft
    /// delete, or discovered gone when the hard delete is attempted — is
    /// treated as already-deleted success.
    ///
    /// Only meaningful for kinds whose spec carries a `deleted: bool`
    /// (`BlockAffinity`, `IPAMBlock`, `IPAMHandle`); for other kinds this
    /// still injects `"deleted": true` into the spec JSON, but nothing reads
    /// it.
    pub async fn soft_then_hard_delete(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
    ) -> Result<(), CasError> {
        let api = self.dynamic_api(kind, namespace);

        let Some(existing) = api.get_opt(name).await.map_err(|e| map_err(e, Op::Get))? else {
            return Ok(()); // already gone: idempotent
        };
        let uid = existing.metadata.uid.clone();
        let raw_revision = existing
            .metadata
            .resource_version
            .clone()
            .unwrap_or_default();

        let mut obj = existing;
        if let Some(root) = obj.data.as_object_mut() {
            let spec = root.entry("spec").or_insert_with(|| json!({}));
            if let Some(map) = spec.as_object_mut() {
                map.insert("deleted".to_string(), json!(true));
            }
        }
        obj.metadata.resource_version = Some(raw_revision);
        let updated = match api.replace(name, &PostParams::default(), &obj).await {
            Ok(updated) => updated,
            Err(kube::Error::Api(resp)) if resp.code == 404 => return Ok(()), // idempotent
            Err(e) => return Err(map_err(e, Op::Update)),
        };
        let new_revision = updated.metadata.resource_version.unwrap_or_default();

        let dp = DeleteParams {
            preconditions: Some(Preconditions {
                resource_version: Some(new_revision),
                uid,
            }),
            ..DeleteParams::default()
        };
        match api.delete(name, &dp).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(resp)) if resp.code == 404 => Ok(()), // idempotent
            Err(e) => Err(map_err(e, Op::Delete)),
        }
    }

    /// List resources of `kind` carrying the [`LABEL_HOSTNAME_HASH`] label for
    /// `host` — a host-scoped list, standing in for a path-prefix query that
    /// Kubernetes label selectors can't express.
    pub async fn list_by_host(
        &self,
        kind: ResourceKind,
        host: &str,
    ) -> Result<Vec<KddValue>, CasError> {
        let api = self.dynamic_api(kind, None);
        let (label, value) = hostname_hash_label(host);
        let selector = format!("{label}={value}");
        let list = api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|e| map_err(e, Op::List))?;
        list.into_iter().map(to_value).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector from upstream `libcalico-go`: `sha3.Sum256("node-a")`
    /// base32-encoded (std alphabet, no padding). MUST match exactly.
    #[test]
    fn golden_hostname_hash_matches_upstream() {
        assert_eq!(
            hash_hostname_for_label("node-a"),
            "PY3TQE2E3XMTETLM2MJO3UITKPFB27YUJ4T4E5XGPEJON3SM4QAA"
        );
    }

    #[test]
    fn different_hosts_hash_differently() {
        assert_ne!(
            hash_hostname_for_label("node-a"),
            hash_hostname_for_label("node-b")
        );
    }

    #[test]
    fn hash_output_fits_label_length_limit() {
        // Kubernetes label *values* are capped at 63 characters.
        assert!(hash_hostname_for_label("a-very-long-hostname.example.com").len() <= 63);
        assert!(hash_hostname_for_label("node-a").len() <= 63);
    }

    #[test]
    fn hostname_hash_label_pairs_key_and_hash() {
        let (key, value) = hostname_hash_label("node-a");
        assert_eq!(key, LABEL_HOSTNAME_HASH);
        assert_eq!(value, hash_hostname_for_label("node-a"));
    }
}
