//! `calico` CNI plugin binary. The ADD/DEL netlink+netns execution is added with
//! the dataplane work; the pure config/identity/naming logic lives in the lib.

fn main() {
    eprintln!(
        "calico CNI: dataplane execution not yet implemented \
         (see specs/001-calico-rs-rust-rewrite/tasks.md; pure logic in the `cni` lib)"
    );
    std::process::exit(1);
}
