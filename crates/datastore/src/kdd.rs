//! KDD — the Kubernetes Datastore Driver.
//!
//! Implements the compare-and-swap datastore operations against the Kubernetes
//! API using kube-rs's *dynamic* API, so it works over any
//! `crd.projectcalico.org/v1` resource without a typed CRD binding. Calico
//! resources are stored as CRDs; the spec is carried as an opaque
//! `serde_json::Value` (the typed `apis` specs (de)serialize to/from it).
//!
//! CAS maps directly to Kubernetes optimistic concurrency: `update` and `delete`
//! carry the `resourceVersion`, and the API server returns 409 Conflict on a
//! mismatch — surfaced here as [`CasError::Conflict`].

use kube::api::{
    ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
    Preconditions,
};
use kube::core::GroupVersionKind;
use kube::{Api, Client};
use serde_json::{json, Value};

use crate::cas::{CasError, Revision};
use crate::model::ResourceKind;

const GROUP: &str = "crd.projectcalico.org";
const VERSION: &str = "v1";

/// A value read from the datastore: its spec plus the resource version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KddValue {
    pub name: String,
    pub spec: Value,
    /// Kubernetes `resourceVersion`, parsed to our numeric [`Revision`].
    pub revision: Revision,
    pub raw_revision: String,
}

/// A datastore backend backed by the Kubernetes API (CRDs).
#[derive(Clone)]
pub struct KddBackend {
    client: Client,
}

impl KddBackend {
    /// Build a backend from an existing kube client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// The underlying kube client (for callers that also need core K8s APIs,
    /// e.g. controllers watching Namespaces/Pods).
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Build a backend from the ambient kube config (`$KUBECONFIG` / in-cluster).
    pub async fn try_default() -> Result<Self, CasError> {
        let client = Client::try_default()
            .await
            .map_err(|e| CasError::Backend(e.to_string()))?;
        Ok(Self::new(client))
    }

    /// Build a backend from a specific kubeconfig file (e.g. the local
    /// `.cluster/calico-rs-k0s.kubeconfig`). Keeps kube-rs an internal detail so
    /// callers/tests only need the datastore public API.
    pub async fn from_kubeconfig_file(path: &str) -> Result<Self, CasError> {
        use kube::config::{Config, KubeConfigOptions, Kubeconfig};
        let kc = Kubeconfig::read_from(path).map_err(|e| CasError::Backend(e.to_string()))?;
        let cfg = Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default())
            .await
            .map_err(|e| CasError::Backend(e.to_string()))?;
        let client = Client::try_from(cfg).map_err(|e| CasError::Backend(e.to_string()))?;
        Ok(Self::new(client))
    }

    fn api_resource(kind: ResourceKind) -> ApiResource {
        let gvk = GroupVersionKind::gvk(GROUP, VERSION, kind.kind_name());
        ApiResource::from_gvk_with_plural(&gvk, kind.as_str())
    }

    pub(crate) fn dynamic_api(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
    ) -> Api<DynamicObject> {
        self.api(kind, namespace)
    }

    fn api(&self, kind: ResourceKind, namespace: Option<&str>) -> Api<DynamicObject> {
        let ar = Self::api_resource(kind);
        match namespace {
            Some(ns) => Api::namespaced_with(self.client.clone(), ns, &ar),
            None => Api::all_with(self.client.clone(), &ar),
        }
    }

    /// Create a resource with the given spec. Errors [`CasError::AlreadyExists`]
    /// if it already exists.
    pub async fn create(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
        spec: Value,
    ) -> Result<KddValue, CasError> {
        let api = self.api(kind, namespace);
        let ar = Self::api_resource(kind);
        let mut obj = DynamicObject::new(name, &ar);
        obj.data = json!({ "spec": spec });
        let created = api
            .create(&PostParams::default(), &obj)
            .await
            .map_err(|e| map_err(e, Op::Create))?;
        to_value(created)
    }

    /// Fetch a resource, or `None` if it does not exist.
    pub async fn get(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
    ) -> Result<Option<KddValue>, CasError> {
        let api = self.api(kind, namespace);
        match api.get_opt(name).await.map_err(|e| map_err(e, Op::Get))? {
            Some(obj) => Ok(Some(to_value(obj)?)),
            None => Ok(None),
        }
    }

    /// Replace a resource's spec iff its current revision matches `revision`
    /// (compare-and-swap). Errors [`CasError::Conflict`] on mismatch.
    pub async fn update(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
        spec: Value,
        raw_revision: &str,
    ) -> Result<KddValue, CasError> {
        let api = self.api(kind, namespace);
        let ar = Self::api_resource(kind);
        let mut obj = DynamicObject::new(name, &ar);
        obj.metadata.resource_version = Some(raw_revision.to_string());
        obj.data = json!({ "spec": spec });
        let updated = api
            .replace(name, &PostParams::default(), &obj)
            .await
            .map_err(|e| map_err(e, Op::Update))?;
        to_value(updated)
    }

    /// Delete a resource iff its current revision matches `raw_revision`.
    pub async fn delete(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
        raw_revision: &str,
    ) -> Result<(), CasError> {
        let api = self.api(kind, namespace);
        let dp = DeleteParams {
            preconditions: Some(Preconditions {
                resource_version: Some(raw_revision.to_string()),
                uid: None,
            }),
            ..DeleteParams::default()
        };
        api.delete(name, &dp)
            .await
            .map_err(|e| map_err(e, Op::Delete))?;
        Ok(())
    }

    /// Apply a JSON merge patch (RFC 7386) to a resource — e.g. a metadata-only
    /// label change that must not disturb `spec`. If `revision` is given it is
    /// added as an optimistic-concurrency precondition (409 on mismatch). Note:
    /// merge-patch merges maps recursively (a `null` value removes a key), so use
    /// it for surgical metadata edits, not full-spec replacement (that is
    /// [`Self::update`], a PUT).
    pub async fn merge_patch(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
        name: &str,
        mut patch: Value,
        revision: Option<&str>,
    ) -> Result<KddValue, CasError> {
        if let Some(rev) = revision {
            let obj = patch
                .as_object_mut()
                .ok_or_else(|| CasError::Backend("patch must be a JSON object".into()))?;
            obj.entry("metadata")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| CasError::Backend("metadata must be an object".into()))?
                .insert("resourceVersion".to_string(), json!(rev));
        }
        let api = self.api(kind, namespace);
        let patched = api
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| map_err(e, Op::Update))?;
        to_value(patched)
    }

    /// List all resources of `kind` (in `namespace`, or cluster-wide).
    pub async fn list(
        &self,
        kind: ResourceKind,
        namespace: Option<&str>,
    ) -> Result<Vec<KddValue>, CasError> {
        let api = self.api(kind, namespace);
        let list = api
            .list(&ListParams::default())
            .await
            .map_err(|e| map_err(e, Op::List))?;
        list.into_iter().map(to_value).collect()
    }
}

enum Op {
    Create,
    Get,
    Update,
    Delete,
    List,
}

fn map_err(e: kube::Error, op: Op) -> CasError {
    match e {
        kube::Error::Api(resp) => match resp.code {
            404 => CasError::NotFound,
            409 => match op {
                Op::Create => CasError::AlreadyExists,
                _ => CasError::Conflict {
                    expected: 0,
                    actual: None,
                },
            },
            _ => CasError::Backend(resp.message),
        },
        other => CasError::Backend(other.to_string()),
    }
}

fn to_value(obj: DynamicObject) -> Result<KddValue, CasError> {
    let name = obj
        .metadata
        .name
        .clone()
        .ok_or_else(|| CasError::Backend("object has no name".into()))?;
    let raw_revision = obj.metadata.resource_version.clone().unwrap_or_default();
    let revision = raw_revision.parse::<Revision>().unwrap_or(0);
    let spec = obj
        .data
        .get("spec")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    Ok(KddValue {
        name,
        spec,
        revision,
        raw_revision,
    })
}
