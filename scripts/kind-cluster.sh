#!/usr/bin/env bash
# Manage the local kind cluster for calico-rs conformance/dev work.
#
# 1 control-plane + 3 workers, no default CNI (calico-rs provides it). Mirrors
# upstream Calico's e2e topology. Distinct name so it does not collide with
# other agents' kind clusters. The kubeconfig kind writes is redirected to
# .cluster/calico-rs-kind.kubeconfig (gitignored).
#
# Usage: scripts/kind-cluster.sh {up|down|destroy|status|kubeconfig|kubectl <args...>|load <image>}
set -euo pipefail

NAME="calico-rs-kind"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/deploy/kind-config.yaml"
KUBECONFIG_PATH="$REPO_ROOT/.cluster/calico-rs-kind.kubeconfig"

up() {
  mkdir -p "$REPO_ROOT/.cluster"
  if kind get clusters 2>/dev/null | grep -qx "$NAME"; then
    echo "cluster $NAME already exists"
  else
    kind create cluster --name "$NAME" --config "$CONFIG" --kubeconfig "$KUBECONFIG_PATH"
  fi
  kind get kubeconfig --name "$NAME" >"$KUBECONFIG_PATH"
  echo "cluster up; KUBECONFIG=$KUBECONFIG_PATH"
  echo "(nodes start NotReady until the calico-rs CNI is installed)"
}

down()    { kind delete cluster --name "$NAME"; }
destroy() { kind delete cluster --name "$NAME"; rm -f "$KUBECONFIG_PATH"; }

status() {
  kind get clusters 2>/dev/null | grep -qx "$NAME" || { echo "cluster $NAME does not exist"; return; }
  KUBECONFIG="$KUBECONFIG_PATH" kubectl get nodes -o wide 2>/dev/null || true
}

# Load a locally-built image into all kind nodes (no registry needed).
load() { kind load docker-image --name "$NAME" "$1"; }

cmd="${1:-}"; shift || true
case "$cmd" in
  up) up ;;
  down) down ;;
  destroy) destroy ;;
  status) status ;;
  kubeconfig) echo "$KUBECONFIG_PATH" ;;
  kubectl) KUBECONFIG="$KUBECONFIG_PATH" kubectl "$@" ;;
  load) load "$@" ;;
  *) echo "usage: $0 {up|down|destroy|status|kubeconfig|kubectl <args...>|load <image>}" >&2; exit 2 ;;
esac
