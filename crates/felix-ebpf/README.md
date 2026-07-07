# felix-ebpf

Kernel-side eBPF programs for the Calico-rs eBPF dataplane (US3 / tasks T063–T069).

**Toolchain**: nightly (pinned via `rust-toolchain.toml` in this directory) +
`rust-src`. Requires the BPF linker:

```bash
cargo install bpf-linker
```

Build (from this directory, once real `aya-ebpf` programs land):

```bash
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

The rest of the workspace builds on stable and CI excludes this crate from the
stable build job (see `.github/workflows/ci.yml`). Currently a stable-compilable
stub; the `no_std` / `aya-ebpf` program code is added by the US3 tasks.
