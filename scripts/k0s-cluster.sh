#!/usr/bin/env bash
# Manage the local single-node k0s dev cluster for calico-rs.
#
# Distinct name/network/port so it does not collide with other agents' k0s
# clusters in Docker. The admin kubeconfig is written to
# .cluster/calico-rs-k0s.kubeconfig (gitignored) and targets the published host
# port, so `kubectl --kubeconfig .cluster/calico-rs-k0s.kubeconfig ...` works
# from the host.
#
# Usage: scripts/k0s-cluster.sh {up|down|status|kubeconfig|kubectl <args...>|exec <args...>}
set -euo pipefail

IMAGE="k0sproject/k0s:v1.35.5-k0s.0"
NAME="calico-rs-k0s-controller"
NET="calico-rs-k0s-net"
VOL="calico-rs-k0s-vol"
HOST_PORT="16443"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECONFIG_PATH="$REPO_ROOT/.cluster/calico-rs-k0s.kubeconfig"

up() {
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    docker start "$NAME" >/dev/null
  else
    docker run -d --name "$NAME" --hostname "$NAME" --privileged \
      --network "$NET" -v "$VOL:/var/lib/k0s" -p "$HOST_PORT:6443" \
      "$IMAGE" k0s controller --enable-worker --no-taints >/dev/null
  fi
  echo "waiting for API..."
  for _ in $(seq 1 40); do
    if docker exec "$NAME" k0s kubectl get --raw='/readyz' >/dev/null 2>&1; then
      break
    fi
    sleep 3
  done
  kubeconfig
  echo "cluster up; KUBECONFIG=$KUBECONFIG_PATH"
}

kubeconfig() {
  mkdir -p "$REPO_ROOT/.cluster"
  docker exec "$NAME" k0s kubeconfig admin >"$KUBECONFIG_PATH" 2>/dev/null
  sed -i "s#server: https://localhost:6443#server: https://127.0.0.1:$HOST_PORT#; s#server: https://[0-9.]*:6443#server: https://127.0.0.1:$HOST_PORT#" "$KUBECONFIG_PATH"
}

down() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "removed $NAME (volume $VOL and network $NET kept; use 'destroy' to remove them)"
}

destroy() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "destroyed cluster, volume, and network"
}

status() {
  docker ps --filter "name=$NAME" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
  docker exec "$NAME" k0s status 2>/dev/null || true
}

cmd="${1:-}"; shift || true
case "$cmd" in
  up) up ;;
  down) down ;;
  destroy) destroy ;;
  status) status ;;
  kubeconfig) kubeconfig; echo "$KUBECONFIG_PATH" ;;
  kubectl) KUBECONFIG="$KUBECONFIG_PATH" kubectl "$@" ;;
  exec) docker exec "$NAME" "$@" ;;
  *) echo "usage: $0 {up|down|destroy|status|kubeconfig|kubectl <args...>|exec <args...>}" >&2; exit 2 ;;
esac
