//! Host-wide IPAM advisory file lock ("lock then clock").
//!
//! kubelet wires pods in parallel, so several `calico` invocations can run at
//! once on a node. Upstream serializes IPAM with an advisory `flock(2)` on a host
//! path so concurrent ADDs don't race pool/block selection and thrash the
//! compare-and-swap datastore. We reproduce that with a raw `flock(2)` — no new
//! external dependency, one small `unsafe` FFI declaration.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::path::Path;

/// Default host lock path (matches upstream `/var/lib/calico`).
pub const DEFAULT_LOCK_PATH: &str = "/var/lib/calico/cni.lock";

// flock(2). LOCK_EX = 2 (exclusive), LOCK_NB = 4 (non-blocking), LOCK_UN = 8.
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

extern "C" {
    fn flock(fd: c_int, operation: c_int) -> c_int;
}

/// An acquired advisory lock. Releasing happens on drop (both an explicit
/// `LOCK_UN` and the fd close release it), so the lock is held for exactly the
/// lifetime of this guard.
#[derive(Debug)]
pub struct HostLock {
    file: File,
}

impl HostLock {
    fn open(path: &Path) -> Result<File, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create lock dir {}: {e}", parent.display()))?;
            }
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| format!("open lock {}: {e}", path.display()))
    }

    /// Acquire the lock, blocking until it is available.
    pub fn acquire(path: &Path) -> Result<HostLock, String> {
        let file = Self::open(path)?;
        // SAFETY: `file` owns a valid open fd for the duration of the call.
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
        if rc != 0 {
            return Err(format!(
                "flock {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(HostLock { file })
    }

    /// Try to acquire the lock without blocking. Returns `Ok(None)` if another
    /// holder currently owns it.
    pub fn try_acquire(path: &Path) -> Result<Option<HostLock>, String> {
        let file = Self::open(path)?;
        // SAFETY: `file` owns a valid open fd for the duration of the call.
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
        if rc == 0 {
            return Ok(Some(HostLock { file }));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // EWOULDBLOCK / EAGAIN: held by someone else.
            Some(libc_ewouldblock) if libc_ewouldblock == EWOULDBLOCK => Ok(None),
            _ => Err(format!("flock {}: {err}", path.display())),
        }
    }
}

// EWOULDBLOCK == EAGAIN == 11 on Linux.
const EWOULDBLOCK: i32 = 11;

impl Drop for HostLock {
    fn drop(&mut self) {
        // SAFETY: fd is valid until `file` is dropped (immediately after this).
        unsafe {
            flock(self.file.as_raw_fd(), LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_exclusive_then_released_on_drop() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("calico-cni-lock-test-{}.lock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let held = HostLock::acquire(&path).expect("acquire");
        // A second, non-blocking attempt must fail while the first is held.
        assert!(
            HostLock::try_acquire(&path)
                .expect("try_acquire call")
                .is_none(),
            "lock should be contended while held"
        );

        drop(held);
        // Once released, the lock is available again.
        let again = HostLock::try_acquire(&path)
            .expect("try_acquire after release")
            .expect("lock should be free after drop");
        drop(again);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn acquire_creates_missing_parent_dir() {
        let dir = std::env::temp_dir().join(format!("calico-lockdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("cni.lock");
        let g = HostLock::acquire(&path).expect("acquire in fresh dir");
        assert!(path.exists());
        drop(g);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
