//! Single-instance lock, the equivalent of Jenkins' `disableConcurrentBuilds()`.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::report::now_rfc3339;

#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;

        match file.try_lock() {
            Ok(()) => {
                let mut handle = &file;
                let _ = handle.set_len(0);
                let _ = writeln!(
                    handle,
                    "pid={} started={} tool={}",
                    std::process::id(),
                    now_rfc3339(),
                    env!("CARGO_PKG_NAME")
                );
                Ok(Self { _file: file })
            }
            Err(TryLockError::WouldBlock) => Err(Error::Locked(PathBuf::from(path))),
            Err(TryLockError::Error(error)) => Err(Error::Io(error)),
        }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_can_be_reacquired_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.lock");
        let first = InstanceLock::acquire(&path).unwrap();
        drop(first);
        let _second = InstanceLock::acquire(&path).unwrap();
    }

    #[test]
    fn second_holder_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.lock");
        let _first = InstanceLock::acquire(&path).unwrap();
        let error = InstanceLock::acquire(&path).unwrap_err();
        assert!(matches!(error, Error::Locked(ref locked) if locked == &path));
    }

    #[test]
    fn lock_writes_metadata_and_creates_parents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/audit.lock");
        let _lock = InstanceLock::acquire(&path).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("pid="));
        assert!(contents.contains(env!("CARGO_PKG_NAME")));
    }

    #[test]
    fn directory_paths_are_rejected_as_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let error = InstanceLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(error, Error::Io(_)));
    }
}
