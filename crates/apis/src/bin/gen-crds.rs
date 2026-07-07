//! Print the Calico-rs CRD manifests (multi-doc YAML) to stdout.
//!
//! Usage: `cargo run -p apis --bin gen-crds | kubectl apply -f -`

fn main() {
    print!("{}", apis::crd::crd_yaml());
}
