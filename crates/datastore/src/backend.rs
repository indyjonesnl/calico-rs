//! The typed async [`Backend`] trait — the single abstraction over typed
//! [`Key`]/[`KVPair`] with list/watch that every higher layer (syncers, update
//! processors, typha, felix, controllers) consumes.
//!
//! This is layered *on top of* the compare-and-swap core ([`crate::CasStore`])
//! and the concrete [`KddBackend`] inherent methods: the trait impls delegate to
//! those, so the existing callers keep working unchanged. Two implementations
//! ship here: [`KddBackend`] (Kubernetes) and [`MemBackend`] (in-memory, for
//! unit-testing the trait without a cluster).

use std::sync::Mutex;

use futures::stream::{BoxStream, StreamExt};
use serde_json::Value;

use crate::cas::{CasError, CasStore, Revision};
use crate::kdd::{KddBackend, KddValue};
use crate::mem::MemStore;
use crate::model::{cidr_to_token, KVPair, Key, ResourceKind};
use crate::syncer::{SyncerEvent, UpdateType};

/// Errors surfaced by a [`Backend`]. Mirrors upstream Calico's
/// `libcalico-go/lib/errors` taxonomy that the retry loops key off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsError {
    /// A compare-and-swap update lost: the supplied revision did not match the
    /// stored one. The caller should re-read and retry.
    ResourceUpdateConflict,
    /// The resource does not exist.
    ResourceDoesNotExist,
    /// `create` was called for a resource that already exists.
    ResourceAlreadyExists,
    /// The backend does not support this operation (e.g. `watch` on the
    /// in-memory backend).
    OperationNotSupported,
    /// A transport / backend failure.
    Datastore(String),
}

impl std::fmt::Display for DsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsError::ResourceUpdateConflict => write!(f, "resource update conflict"),
            DsError::ResourceDoesNotExist => write!(f, "resource does not exist"),
            DsError::ResourceAlreadyExists => write!(f, "resource already exists"),
            DsError::OperationNotSupported => write!(f, "operation not supported"),
            DsError::Datastore(s) => write!(f, "datastore error: {s}"),
        }
    }
}

impl std::error::Error for DsError {}

impl From<CasError> for DsError {
    fn from(e: CasError) -> Self {
        match e {
            CasError::NotFound => DsError::ResourceDoesNotExist,
            CasError::AlreadyExists => DsError::ResourceAlreadyExists,
            CasError::Conflict { .. } => DsError::ResourceUpdateConflict,
            CasError::Backend(s) => DsError::Datastore(s),
        }
    }
}

/// Selects the resources a [`Backend::list`] / [`Backend::watch`] operates over:
/// a whole kind, one namespace of it, or a single named item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOptions {
    pub kind: ResourceKind,
    pub namespace: Option<String>,
    /// `Some` ⇒ a single-item list; `None` ⇒ all items of the kind.
    pub name: Option<String>,
}

impl ListOptions {
    /// List every item of `kind` (all namespaces for namespaced kinds).
    pub fn kind(kind: ResourceKind) -> Self {
        Self {
            kind,
            namespace: None,
            name: None,
        }
    }

    /// Restrict to `namespace`.
    pub fn in_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Restrict to a single named item.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// The result of a [`Backend::list`]: the items plus the revision the list was
/// taken at (the collection resourceVersion, for a subsequent watch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KVPairList {
    pub items: Vec<KVPair<Value>>,
    pub revision: Revision,
}

/// One data event from a [`Backend::watch`] stream. Reuses the syncer's
/// [`UpdateType`]; status transitions are the syncer's concern and are not
/// surfaced here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub kv: KVPair<Value>,
    pub event_type: UpdateType,
}

/// The typed datastore backend. Compare-and-swap semantics: [`Backend::update`]
/// fails with [`DsError::ResourceUpdateConflict`] if the supplied revision does
/// not match the stored one.
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    /// Create `kv`. Errors [`DsError::ResourceAlreadyExists`] if it exists.
    async fn create(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError>;
    /// Replace `kv` iff its stored revision equals `kv.revision` (CAS).
    async fn update(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError>;
    /// Upsert: create if absent, otherwise replace (ignores `kv.revision`).
    async fn apply(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError>;
    /// Fetch `key`. Errors [`DsError::ResourceDoesNotExist`] if absent.
    async fn get(&self, key: &Key) -> Result<KVPair<Value>, DsError>;
    /// Delete `key`; with `revision = Some(_)` the delete is a CAS.
    async fn delete(&self, key: &Key, revision: Option<Revision>) -> Result<(), DsError>;
    /// List the resources selected by `opts`.
    async fn list(&self, opts: &ListOptions) -> Result<KVPairList, DsError>;
    /// Watch the resources selected by `opts`, yielding data events.
    async fn watch(
        &self,
        opts: &ListOptions,
    ) -> Result<BoxStream<'static, Result<WatchEvent, DsError>>, DsError>;
    /// Ensure the datastore is ready (CRDs present, etc.).
    async fn ensure_initialized(&self) -> Result<(), DsError>;
}

// ---- Key → (kind, namespace, name) mapping -------------------------------

/// Coerce an arbitrary id into an RFC-1123-ish resource name. Matches
/// `crates/ipam/src/kdd.rs::sanitize_name` so IPAM keys resolve to the same CR
/// names the IPAM allocator uses.
fn sanitize_name(s: &str) -> String {
    let mut out: String = s
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    out.truncate(253);
    out
}

/// Map a typed [`Key`] to the `(kind, namespace, name)` triple the underlying
/// KDD calls take. IPAM key → CR-name derivation matches `KddIpam`
/// (`crates/ipam/src/kdd.rs`): block name is the CIDR token; affinity name is
/// `sanitize("{host}-{cidr_token}")`; handle name is `sanitize(id)`.
pub fn key_to_target(key: &Key) -> (ResourceKind, Option<String>, String) {
    match key {
        Key::Resource {
            kind,
            namespace,
            name,
        } => (*kind, namespace.clone(), name.clone()),
        Key::Block { cidr } => (ResourceKind::IpamBlock, None, cidr_to_token(cidr)),
        Key::BlockAffinity { host, cidr } => (
            ResourceKind::BlockAffinity,
            None,
            sanitize_name(&format!("{}-{}", host, cidr_to_token(cidr))),
        ),
        Key::IpamHandle { id } => (ResourceKind::IpamHandle, None, sanitize_name(id)),
    }
}

/// Reconstruct the namespaced [`Key`] for one item of a KDD list: prefer the
/// item's own `metadata.namespace` (so a cluster-wide list of a namespaced kind
/// keeps each item in its own namespace and same-named items in different
/// namespaces stay distinct), falling back to the list's namespace when the
/// item carries none (cluster-scoped kinds).
fn list_item_key(kind: ResourceKind, opts_namespace: Option<&str>, v: &KddValue) -> Key {
    Key::Resource {
        kind,
        namespace: v
            .namespace
            .clone()
            .or_else(|| opts_namespace.map(str::to_string)),
        name: v.name.clone(),
    }
}

// ---- In-memory backend ----------------------------------------------------

/// An in-memory [`Backend`] backed by [`MemStore`], for unit-testing the trait
/// and the CAS-dependent logic above it without a live cluster. Keyed by
/// [`Key::path`]; the stored value carries its [`Key`] so lists can reconstruct
/// typed pairs.
pub struct MemBackend {
    store: Mutex<MemStore<(Key, Value)>>,
}

impl MemBackend {
    /// An empty in-memory backend.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(MemStore::new()),
        }
    }
}

impl Default for MemBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Backend for MemBackend {
    async fn create(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError> {
        let path = kv.key.path();
        let mut store = self.store.lock().expect("mem backend poisoned");
        let v = store.create(&path, (kv.key.clone(), kv.value.clone()))?;
        Ok(KVPair::with_revision(kv.key, kv.value, v.revision))
    }

    async fn update(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError> {
        let rev = kv
            .revision
            .ok_or_else(|| DsError::Datastore("update requires a revision".into()))?;
        let path = kv.key.path();
        let mut store = self.store.lock().expect("mem backend poisoned");
        let v = store.update(&path, (kv.key.clone(), kv.value.clone()), rev)?;
        Ok(KVPair::with_revision(kv.key, kv.value, v.revision))
    }

    async fn apply(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError> {
        let path = kv.key.path();
        let mut store = self.store.lock().expect("mem backend poisoned");
        let value = (kv.key.clone(), kv.value.clone());
        let v = match store.create(&path, value.clone()) {
            Ok(v) => v,
            Err(CasError::AlreadyExists) => {
                let current = store.get(&path).ok_or(DsError::ResourceDoesNotExist)?;
                store.update(&path, value, current.revision)?
            }
            Err(e) => return Err(e.into()),
        };
        Ok(KVPair::with_revision(kv.key, kv.value, v.revision))
    }

    async fn get(&self, key: &Key) -> Result<KVPair<Value>, DsError> {
        let store = self.store.lock().expect("mem backend poisoned");
        match store.get(&key.path()) {
            Some(v) => Ok(KVPair::with_revision(key.clone(), v.value.1, v.revision)),
            None => Err(DsError::ResourceDoesNotExist),
        }
    }

    async fn delete(&self, key: &Key, revision: Option<Revision>) -> Result<(), DsError> {
        let path = key.path();
        let mut store = self.store.lock().expect("mem backend poisoned");
        let rev = match revision {
            Some(r) => r,
            None => {
                store
                    .get(&path)
                    .ok_or(DsError::ResourceDoesNotExist)?
                    .revision
            }
        };
        store.delete(&path, rev)?;
        Ok(())
    }

    async fn list(&self, opts: &ListOptions) -> Result<KVPairList, DsError> {
        let store = self.store.lock().expect("mem backend poisoned");
        // Prefix over `Key::path`: `/{plural}` for a whole kind, `/{plural}/{ns}`
        // when a namespace is given. A trailing `/` prevents a plural that is a
        // prefix of another from matching (and delimits the namespace segment).
        let mut prefix = format!("/{}/", opts.kind.as_str());
        if let Some(ns) = &opts.namespace {
            prefix.push_str(ns);
            prefix.push('/');
        }
        let items: Vec<KVPair<Value>> = store
            .list(&prefix)
            .into_iter()
            .filter(|v| {
                opts.name
                    .as_ref()
                    .is_none_or(|n| key_to_target(&v.value.0).2 == *n)
            })
            .map(|v| KVPair::with_revision(v.value.0.clone(), v.value.1.clone(), v.revision))
            .collect();
        Ok(KVPairList {
            revision: store.revision(),
            items,
        })
    }

    async fn watch(
        &self,
        _opts: &ListOptions,
    ) -> Result<BoxStream<'static, Result<WatchEvent, DsError>>, DsError> {
        Err(DsError::OperationNotSupported)
    }

    async fn ensure_initialized(&self) -> Result<(), DsError> {
        Ok(())
    }
}

/// Validate a caller-supplied revision for a CAS `update`: require `Some` and
/// non-zero.
///
/// A revision of `0` only ever arises from a failed parse of the raw K8s
/// `resourceVersion` (see `kdd.rs`'s `unwrap_or(0)` fallback), never from a
/// real `resourceVersion`. Kubernetes treats `resourceVersion: "0"` as "match
/// any" for reads, so silently sending it on to [`KddBackend::update`] would
/// defeat the CAS instead of failing loudly — reject it explicitly here.
fn require_nonzero_revision(revision: Option<Revision>) -> Result<Revision, DsError> {
    match revision {
        None | Some(0) => Err(DsError::Datastore(
            "update requires a valid non-zero revision for CAS".into(),
        )),
        Some(rev) => Ok(rev),
    }
}

// ---- KDD backend ----------------------------------------------------------

#[async_trait::async_trait]
impl Backend for KddBackend {
    async fn create(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError> {
        let (kind, ns, name) = key_to_target(&kv.key);
        let v = self.create(kind, ns.as_deref(), &name, kv.value).await?;
        Ok(KVPair::with_revision(kv.key, v.spec, v.revision))
    }

    async fn update(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError> {
        let (kind, ns, name) = key_to_target(&kv.key);
        let rev = require_nonzero_revision(kv.revision)?;
        // Numeric Revision → raw resourceVersion string: for CRDs the K8s
        // resourceVersion *is* a numeric string, and `to_value` obtains the
        // numeric revision by parsing it, so `rev.to_string()` reconstructs the
        // exact token losslessly — and without a re-read that would open a
        // TOCTOU window and defeat the CAS.
        let raw = rev.to_string();
        let v = self
            .update(kind, ns.as_deref(), &name, kv.value, &raw)
            .await?;
        Ok(KVPair::with_revision(kv.key, v.spec, v.revision))
    }

    async fn apply(&self, kv: KVPair<Value>) -> Result<KVPair<Value>, DsError> {
        let (kind, ns, name) = key_to_target(&kv.key);
        // Upsert: use the *current* raw revision for the update leg so the PUT
        // succeeds regardless of the caller-supplied revision.
        match self.get(kind, ns.as_deref(), &name).await? {
            Some(existing) => {
                let v = self
                    .update(kind, ns.as_deref(), &name, kv.value, &existing.raw_revision)
                    .await?;
                Ok(KVPair::with_revision(kv.key, v.spec, v.revision))
            }
            None => {
                let v = self.create(kind, ns.as_deref(), &name, kv.value).await?;
                Ok(KVPair::with_revision(kv.key, v.spec, v.revision))
            }
        }
    }

    async fn get(&self, key: &Key) -> Result<KVPair<Value>, DsError> {
        let (kind, ns, name) = key_to_target(key);
        match self.get(kind, ns.as_deref(), &name).await? {
            Some(v) => Ok(KVPair::with_revision(key.clone(), v.spec, v.revision)),
            None => Err(DsError::ResourceDoesNotExist),
        }
    }

    async fn delete(&self, key: &Key, revision: Option<Revision>) -> Result<(), DsError> {
        let (kind, ns, name) = key_to_target(key);
        let raw = match revision {
            Some(r) => r.to_string(),
            None => match self.get(kind, ns.as_deref(), &name).await? {
                Some(v) => v.raw_revision,
                None => return Err(DsError::ResourceDoesNotExist),
            },
        };
        self.delete(kind, ns.as_deref(), &name, &raw).await?;
        Ok(())
    }

    async fn list(&self, opts: &ListOptions) -> Result<KVPairList, DsError> {
        // Single-item list: a targeted get keeps the namespace correct.
        if let Some(name) = &opts.name {
            let key = Key::Resource {
                kind: opts.kind,
                namespace: opts.namespace.clone(),
                name: name.clone(),
            };
            return match self.get(opts.kind, opts.namespace.as_deref(), name).await? {
                Some(v) => Ok(KVPairList {
                    revision: v.revision,
                    items: vec![KVPair::with_revision(key, v.spec, v.revision)],
                }),
                None => Ok(KVPairList {
                    items: Vec::new(),
                    revision: 0,
                }),
            };
        }
        let values = self.list(opts.kind, opts.namespace.as_deref()).await?;
        let mut revision = 0;
        let items = values
            .into_iter()
            .map(|v| {
                revision = revision.max(v.revision);
                let key = list_item_key(opts.kind, opts.namespace.as_deref(), &v);
                KVPair::with_revision(key, v.spec, v.revision)
            })
            .collect();
        Ok(KVPairList { items, revision })
    }

    async fn watch(
        &self,
        opts: &ListOptions,
    ) -> Result<BoxStream<'static, Result<WatchEvent, DsError>>, DsError> {
        // Delegate to the syncer watch, projecting `Update` events into
        // `WatchEvent`s and dropping `Status(..)` transitions: the trait's
        // `watch` yields data events only; sync-status is the syncer's concern
        // (T019). The syncer reconstructs each event's `Key` (with namespace)
        // from the object itself, so watch keys are exact.
        let stream = KddBackend::watch(self, opts.kind, opts.namespace.as_deref()).filter_map(
            |res| async move {
                match res {
                    Ok(SyncerEvent::Status(_)) => None,
                    Ok(SyncerEvent::Update {
                        key,
                        spec,
                        revision,
                        update_type,
                        // `WatchEvent` (this trait's generic KVPair-based watch
                        // event) has no label field; labels are consumed by the
                        // felix calc-graph path, not this generic backend watch.
                        ..
                    }) => Some(Ok(WatchEvent {
                        kv: KVPair::with_revision(key, spec, revision),
                        event_type: update_type,
                    })),
                    Err(e) => Some(Err(e.into())),
                }
            },
        );
        Ok(stream.boxed())
    }

    async fn ensure_initialized(&self) -> Result<(), DsError> {
        // CRD / ClusterInformation bootstrap is a later task (T017); the KDD
        // backend assumes the calico CRDs are already installed.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Compile-time proof that the concrete KDD backend satisfies the trait
    /// (its behaviour is covered by the live-cluster integration tests).
    #[allow(dead_code)]
    fn _assert_kdd_is_backend(b: &KddBackend) -> &dyn Backend {
        b
    }

    #[test]
    fn require_nonzero_revision_rejects_none_and_zero() {
        assert_eq!(
            require_nonzero_revision(None).unwrap_err(),
            DsError::Datastore("update requires a valid non-zero revision for CAS".into())
        );
        assert_eq!(
            require_nonzero_revision(Some(0)).unwrap_err(),
            DsError::Datastore("update requires a valid non-zero revision for CAS".into())
        );
    }

    #[test]
    fn require_nonzero_revision_accepts_nonzero() {
        assert_eq!(require_nonzero_revision(Some(42)).unwrap(), 42);
    }

    fn res_key(kind: ResourceKind, ns: Option<&str>, name: &str) -> Key {
        Key::Resource {
            kind,
            namespace: ns.map(str::to_string),
            name: name.to_string(),
        }
    }

    #[tokio::test]
    async fn create_then_get_roundtrip() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::IpPool, None, "pool-a");
        let created = b
            .create(KVPair::new(key.clone(), json!({"cidr": "10.0.0.0/16"})))
            .await
            .unwrap();
        assert!(created.revision.is_some());
        assert_eq!(created.value, json!({"cidr": "10.0.0.0/16"}));

        let got = b.get(&key).await.unwrap();
        assert_eq!(got.key, key);
        assert_eq!(got.value, json!({"cidr": "10.0.0.0/16"}));
        assert_eq!(got.revision, created.revision);
    }

    #[tokio::test]
    async fn create_existing_is_already_exists() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::IpPool, None, "dup");
        b.create(KVPair::new(key.clone(), json!({}))).await.unwrap();
        let err = b.create(KVPair::new(key, json!({}))).await.unwrap_err();
        assert_eq!(err, DsError::ResourceAlreadyExists);
    }

    #[tokio::test]
    async fn get_missing_is_does_not_exist() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::Node, None, "ghost");
        assert_eq!(
            b.get(&key).await.unwrap_err(),
            DsError::ResourceDoesNotExist
        );
    }

    #[tokio::test]
    async fn update_cas_conflict_then_success() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::FelixConfiguration, None, "default");
        let created = b
            .create(KVPair::new(key.clone(), json!({"n": 1})))
            .await
            .unwrap();
        let good_rev = created.revision.unwrap();

        // Stale revision loses.
        let stale = KVPair::with_revision(key.clone(), json!({"n": 2}), good_rev + 999);
        assert_eq!(
            b.update(stale).await.unwrap_err(),
            DsError::ResourceUpdateConflict
        );

        // Correct revision wins and bumps the revision.
        let updated = b
            .update(KVPair::with_revision(
                key.clone(),
                json!({"n": 3}),
                good_rev,
            ))
            .await
            .unwrap();
        assert_eq!(updated.value, json!({"n": 3}));
        assert_ne!(updated.revision, created.revision);

        // The now-stale original revision conflicts.
        assert_eq!(
            b.update(KVPair::with_revision(key, json!({"n": 4}), good_rev))
                .await
                .unwrap_err(),
            DsError::ResourceUpdateConflict
        );
    }

    #[tokio::test]
    async fn update_missing_is_does_not_exist() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::Node, None, "ghost");
        let err = b
            .update(KVPair::with_revision(key, json!({}), 1))
            .await
            .unwrap_err();
        assert_eq!(err, DsError::ResourceDoesNotExist);
    }

    #[tokio::test]
    async fn delete_then_get_is_does_not_exist() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::IpPool, None, "gone");
        let created = b.create(KVPair::new(key.clone(), json!({}))).await.unwrap();
        b.delete(&key, created.revision).await.unwrap();
        assert_eq!(
            b.get(&key).await.unwrap_err(),
            DsError::ResourceDoesNotExist
        );
    }

    #[tokio::test]
    async fn delete_with_stale_revision_conflicts() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::IpPool, None, "cas");
        let created = b.create(KVPair::new(key.clone(), json!({}))).await.unwrap();
        let err = b
            .delete(&key, Some(created.revision.unwrap() + 999))
            .await
            .unwrap_err();
        assert_eq!(err, DsError::ResourceUpdateConflict);
    }

    #[tokio::test]
    async fn delete_without_revision_is_unconditional() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::IpPool, None, "any");
        b.create(KVPair::new(key.clone(), json!({}))).await.unwrap();
        b.delete(&key, None).await.unwrap();
        assert_eq!(
            b.get(&key).await.unwrap_err(),
            DsError::ResourceDoesNotExist
        );
        // Deleting a missing key without a revision reports it does not exist.
        assert_eq!(
            b.delete(&key, None).await.unwrap_err(),
            DsError::ResourceDoesNotExist
        );
    }

    #[tokio::test]
    async fn apply_upserts() {
        let b = MemBackend::new();
        let key = res_key(ResourceKind::IpPool, None, "up");
        // create-if-absent
        let first = b
            .apply(KVPair::new(key.clone(), json!({"v": 1})))
            .await
            .unwrap();
        assert_eq!(first.value, json!({"v": 1}));
        // update-if-present (no revision needed for apply)
        let second = b
            .apply(KVPair::new(key.clone(), json!({"v": 2})))
            .await
            .unwrap();
        assert_eq!(second.value, json!({"v": 2}));
        assert_ne!(first.revision, second.revision);
        assert_eq!(b.get(&key).await.unwrap().value, json!({"v": 2}));
    }

    #[tokio::test]
    async fn list_filters_by_kind_and_namespace() {
        let b = MemBackend::new();
        // Two namespaced policies in different namespaces + a different kind.
        b.create(KVPair::new(
            res_key(ResourceKind::NetworkPolicy, Some("ns1"), "p1"),
            json!({}),
        ))
        .await
        .unwrap();
        b.create(KVPair::new(
            res_key(ResourceKind::NetworkPolicy, Some("ns1"), "p2"),
            json!({}),
        ))
        .await
        .unwrap();
        b.create(KVPair::new(
            res_key(ResourceKind::NetworkPolicy, Some("ns2"), "p3"),
            json!({}),
        ))
        .await
        .unwrap();
        b.create(KVPair::new(
            res_key(ResourceKind::IpPool, None, "pool"),
            json!({}),
        ))
        .await
        .unwrap();

        // All network policies (both namespaces).
        let all = b
            .list(&ListOptions::kind(ResourceKind::NetworkPolicy))
            .await
            .unwrap();
        assert_eq!(all.items.len(), 3);
        assert!(all.revision > 0);

        // Only ns1.
        let ns1 = b
            .list(&ListOptions::kind(ResourceKind::NetworkPolicy).in_namespace("ns1"))
            .await
            .unwrap();
        assert_eq!(ns1.items.len(), 2);
        assert!(ns1
            .items
            .iter()
            .all(|kv| matches!(&kv.key, Key::Resource { namespace: Some(n), .. } if n == "ns1")));

        // Only the pool.
        let pools = b
            .list(&ListOptions::kind(ResourceKind::IpPool))
            .await
            .unwrap();
        assert_eq!(pools.items.len(), 1);

        // Single named item.
        let one = b
            .list(
                &ListOptions::kind(ResourceKind::NetworkPolicy)
                    .in_namespace("ns2")
                    .named("p3"),
            )
            .await
            .unwrap();
        assert_eq!(one.items.len(), 1);
        assert_eq!(one.items[0].value, json!({}));
    }

    #[tokio::test]
    async fn mem_watch_is_unsupported() {
        let b = MemBackend::new();
        let err = b
            .watch(&ListOptions::kind(ResourceKind::IpPool))
            .await
            .err()
            .unwrap();
        assert_eq!(err, DsError::OperationNotSupported);
    }

    #[tokio::test]
    async fn ensure_initialized_ok() {
        let b = MemBackend::new();
        b.ensure_initialized().await.unwrap();
    }

    #[test]
    fn cas_error_maps_to_ds_error() {
        assert_eq!(
            DsError::from(CasError::NotFound),
            DsError::ResourceDoesNotExist
        );
        assert_eq!(
            DsError::from(CasError::AlreadyExists),
            DsError::ResourceAlreadyExists
        );
        assert_eq!(
            DsError::from(CasError::Conflict {
                expected: 1,
                actual: Some(2)
            }),
            DsError::ResourceUpdateConflict
        );
        assert_eq!(
            DsError::from(CasError::Backend("boom".into())),
            DsError::Datastore("boom".into())
        );
    }

    fn kdd_value(name: &str, namespace: Option<&str>) -> KddValue {
        KddValue {
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
            spec: json!({}),
            revision: 1,
            raw_revision: "1".to_string(),
        }
    }

    /// Regression (T015 review): a cluster-wide list (`opts.namespace == None`)
    /// of a namespaced kind must reconstruct each item's namespaced key from the
    /// item's own `metadata.namespace`. Two same-named items in different
    /// namespaces must yield distinct keys — before this fix both listed with
    /// `namespace = None` and collided.
    #[test]
    fn list_item_key_preserves_per_item_namespace() {
        let a = kdd_value("dup", Some("ns1"));
        let b = kdd_value("dup", Some("ns2"));

        let ka = list_item_key(ResourceKind::NetworkPolicy, None, &a);
        let kb = list_item_key(ResourceKind::NetworkPolicy, None, &b);

        assert_eq!(ka, res_key(ResourceKind::NetworkPolicy, Some("ns1"), "dup"));
        assert_eq!(kb, res_key(ResourceKind::NetworkPolicy, Some("ns2"), "dup"));
        assert_ne!(
            ka, kb,
            "same-named items in different namespaces must not collide"
        );
        assert_ne!(ka.path(), kb.path());
    }

    /// A namespace-scoped list still labels items lacking their own namespace
    /// with the list's namespace; a cluster-scoped item (no namespace, no opts
    /// namespace) stays cluster-scoped.
    #[test]
    fn list_item_key_namespace_fallback() {
        // Item without its own namespace, listed within a namespace.
        let scoped = list_item_key(
            ResourceKind::NetworkPolicy,
            Some("ns1"),
            &kdd_value("p", None),
        );
        assert_eq!(
            scoped,
            res_key(ResourceKind::NetworkPolicy, Some("ns1"), "p")
        );

        // Cluster-scoped kind: no namespace anywhere.
        let cluster = list_item_key(ResourceKind::IpPool, None, &kdd_value("pool", None));
        assert_eq!(cluster, res_key(ResourceKind::IpPool, None, "pool"));
    }

    #[test]
    fn ipam_key_names_match_kddipam() {
        // Block name = CIDR token (no sanitize), matching KddIpam.
        let (kind, ns, name) = key_to_target(&Key::Block {
            cidr: "10.0.0.0/26".into(),
        });
        assert_eq!(kind, ResourceKind::IpamBlock);
        assert_eq!(ns, None);
        assert_eq!(name, "10-0-0-0-26");

        // Affinity name = sanitize("{host}-{cidr_token}").
        let (kind, _, name) = key_to_target(&Key::BlockAffinity {
            host: "node-1".into(),
            cidr: "10.0.0.0/26".into(),
        });
        assert_eq!(kind, ResourceKind::BlockAffinity);
        assert_eq!(name, "node-1-10-0-0-0-26");

        // Handle name = sanitize(id).
        let (kind, _, name) = key_to_target(&Key::IpamHandle {
            id: "net.ABC/xyz".into(),
        });
        assert_eq!(kind, ResourceKind::IpamHandle);
        assert_eq!(name, "net.abc-xyz");
    }
}
