# calico-rs node image.
#
# The Rust binaries are built statically against musl on the host (see
# scripts/build-image.sh) and copied in, so this stays a thin runtime layer.
# Runtime tools: `nft` (felix programs nftables) and `ip` (iproute2, dataplane).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Static binaries staged by build-image.sh into the build context.
COPY calico-rs-node        /opt/calico-rs/bin/calico-rs-node
COPY calico-rs-controllers /opt/calico-rs/bin/calico-rs-controllers
COPY calico                /opt/calico-rs/bin/calico

RUN chmod 0755 /opt/calico-rs/bin/*

ENTRYPOINT ["/opt/calico-rs/bin/calico-rs-node"]
