# Conformance fixtures (upstream gold oracles)

Fixtures imported from the local upstream reference (`upstream/calico`, gitignored)
and used as test oracles for Calico-rs. See `specs/001-calico-rs-rust-rewrite/research.md`
§"Highest-value upstream conformance fixtures".

Import (run from repo root; upstream/ must be present):

| Fixture set | Upstream source | Used by |
|-------------|-----------------|---------|
| `compiled_templates/` | `upstream/calico/confd/tests/compiled_templates/` | BGP config-render golden tests (T084) |
| `ipam_vectors/` | `upstream/calico/libcalico-go/lib/ipam/` test data | IPAM allocation/release invariants (T110) |
| `bpf_layouts/` | notes derived from `upstream/calico/felix/design/bpf-*.md` | BPF map layout/mark compatibility (T062) |

These are behavioral oracles only — Calico-rs reproduces the *observed outcomes*,
not the Go implementation. Populate lazily as the corresponding test tasks land.
