//! Small filesystem helpers with atomic writes.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Read at most `max_bytes` from `path` as UTF-8, replacing invalid sequences.
///
/// Configuration files are small, but a compromised host could replace one with a huge file.
/// Bounding the read keeps every stage's memory use predictable.
pub fn read_limited(path: &Path, max_bytes: u64) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Write `contents` to `path` atomically: write a unique sibling temp file, fsync it, rename it
/// and fsync the parent directory.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_owned());

    let mut last_error = None;
    for _ in 0..16 {
        // The pid and a process-wide counter make the name unique across threads and concurrent
        // audit instances; `create_new` still rejects a collision with a leftover temp file.
        let tmp = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));

        let result: io::Result<()> = (|| {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)?;
            sync_directory(parent);
            Ok(())
        })();

        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // Do not remove the file: it belongs to another writer.
                last_error = Some(error);
            }
            Err(error) => {
                let _ = fs::remove_file(&tmp);
                return Err(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("could not create a unique temp file")))
}

/// Flush the directory entry so a rename survives a crash. Best effort: the data file is already
/// durable, and some filesystems do not allow directory fsync.
fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(path) {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Resolve `path` to an absolute path when it exists, otherwise return it unchanged.
pub fn absolute_existing(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// List files in `dir` whose extension matches case-insensitively, sorted and truncated.
///
/// Missing or unreadable directories yield an empty list, matching the stages' best-effort
/// configuration discovery.
pub fn files_with_extension(dir: &Path, extension: &str, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.truncate(limit);
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/report.txt");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_reports_parent_failures() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-directory");
        fs::write(&blocker, b"file").unwrap();
        let result = write_atomic(&blocker.join("report.txt"), b"data");
        assert!(result.is_err());
    }

    #[test]
    fn atomic_write_cleans_up_when_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        let result = write_atomic(&target, b"data");
        assert!(result.is_err());
        assert!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp"))
        );
    }

    #[test]
    fn absolute_existing_resolves_existing_paths_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.txt");
        fs::write(&path, b"data").unwrap();
        assert_eq!(absolute_existing(&path), fs::canonicalize(&path).unwrap());

        let missing = dir.path().join("missing.txt");
        assert_eq!(absolute_existing(&missing), missing);
    }

    #[test]
    fn read_limited_caps_the_read_and_replaces_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, b"hello\xffworld").unwrap();
        assert_eq!(read_limited(&path, 5).unwrap(), "hello");
        assert_eq!(read_limited(&path, 1024).unwrap(), "hello\u{fffd}world");
        assert!(read_limited(&dir.path().join("missing"), 10).is_err());
    }
}
