//! Bounded log-file discovery and tail reading.
//!
//! Audits must never read an unbounded production log into memory. These helpers expand the
//! configured files/directories, keep only recent plain-text candidates and return a byte-bounded
//! tail. The first line is dropped when a file is seeked into the middle, so parsers never see a
//! chopped record.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Expand files and directories into a sorted, de-duplicated candidate list.
///
/// Explicit file paths are always kept. Directory entries are filtered with `is_candidate`, which
/// lets each stage ignore rotated/compressed files it cannot parse.
pub fn collect_files(
    roots: &[PathBuf],
    is_candidate: fn(&Path) -> bool,
    limit: usize,
) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    for root in roots {
        if files.len() >= limit {
            break;
        }
        let Ok(metadata) = fs::metadata(root) else {
            continue;
        };
        if metadata.is_file() {
            files.insert(root.clone());
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            if files.len() >= limit {
                break;
            }
            // Use `symlink_metadata` so a symlink in an untrusted log directory cannot point the
            // audit at an arbitrary file outside the configured roots.
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.is_file() && is_candidate(&path) {
                files.insert(path);
            }
        }
    }
    files.into_iter().take(limit).collect()
}

/// Read at most `max_bytes` from the end of a file as UTF-8 (invalid bytes are replaced).
///
/// When the file is larger than the limit the partial first line is discarded.
pub fn read_tail(path: &Path, max_bytes: usize) -> io::Result<String> {
    if max_bytes == 0 {
        return Ok(String::new());
    }

    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes as u64);
    if start > 0 {
        file.seek(SeekFrom::Start(start))?;
    }

    let mut bytes = Vec::with_capacity((max_bytes as u64).min(len) as usize);
    file.take(max_bytes as u64).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);

    if start > 0 {
        if let Some(index) = text.find('\n') {
            return Ok(text[index + 1..].to_owned());
        }
        return Ok(String::new());
    }
    Ok(text.into_owned())
}

/// True when a file name has a compressed suffix. Rotated logs are often gzipped.
pub fn is_compressed(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    [".gz", ".xz", ".bz2", ".zip", ".zst", ".7z"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Render the highest-count entries as `key (count), key (count), ...`.
pub fn top_counts(counts: &std::collections::BTreeMap<String, usize>, limit: usize) -> String {
    let mut entries = counts
        .iter()
        .map(|(key, count)| (key.as_str(), *count))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    entries
        .into_iter()
        .take(limit)
        .map(|(key, count)| format!("{key} ({count})"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_text(path: &Path) -> bool {
        path.extension().is_some_and(|extension| extension == "log")
    }

    #[test]
    fn reads_small_files_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.log");
        fs::write(&path, "one\ntwo\n").unwrap();
        assert_eq!(read_tail(&path, 1024).unwrap(), "one\ntwo\n");
        assert_eq!(read_tail(&path, 0).unwrap(), "");
    }

    #[test]
    fn reads_only_the_tail_and_drops_a_partial_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.log");
        fs::write(&path, "old-line\nmiddle-line\nlast-line\n").unwrap();

        let tail = read_tail(&path, 18).unwrap();
        assert!(tail.contains("last-line"));
        assert!(!tail.contains("old-line"));
        assert!(!tail.starts_with("ddle-line"));
        assert!(tail.lines().all(|line| line.ends_with("line")));
    }

    #[test]
    fn returns_empty_when_the_tail_has_no_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("single.log");
        fs::write(&path, "x".repeat(100)).unwrap();
        assert_eq!(read_tail(&path, 10).unwrap(), "");
    }

    #[test]
    fn handles_missing_and_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_tail(&dir.path().join("missing.log"), 10).is_err());

        let empty = dir.path().join("empty.log");
        fs::write(&empty, "").unwrap();
        assert_eq!(read_tail(&empty, 10).unwrap(), "");
    }

    #[test]
    fn expands_directories_filters_and_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.log");
        let b = dir.path().join("b.log");
        let ignored = dir.path().join("b.txt");
        fs::write(&a, "a").unwrap();
        fs::write(&b, "b").unwrap();
        fs::write(&ignored, "nope").unwrap();

        let roots = vec![
            dir.path().to_path_buf(),
            a.clone(),
            dir.path().join("missing"),
        ];
        let files = collect_files(&roots, is_text, 10);
        assert_eq!(files, vec![a, b]);
    }

    #[test]
    fn explicit_files_ignore_the_candidate_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.txt");
        fs::write(&path, "data").unwrap();
        assert_eq!(
            collect_files(std::slice::from_ref(&path), is_text, 10),
            vec![path]
        );
    }

    #[test]
    fn directory_expansion_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("access.log");
        fs::write(&real, "data").unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link.log")).unwrap();

        let files = collect_files(&[dir.path().to_path_buf()], is_text, 10);
        assert_eq!(files, vec![real]);
    }

    #[test]
    fn respects_the_file_limit() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..10 {
            fs::write(dir.path().join(format!("{index}.log")), "x").unwrap();
        }
        assert_eq!(
            collect_files(&[dir.path().to_path_buf()], is_text, 3).len(),
            3
        );
    }

    #[test]
    fn detects_compressed_suffixes() {
        assert!(is_compressed(Path::new("access.log.1.gz")));
        assert!(is_compressed(Path::new("access.log.xz")));
        assert!(!is_compressed(Path::new("access.log.1")));
        assert!(!is_compressed(Path::new("access.log")));
    }

    #[test]
    fn ranks_counts_deterministically() {
        let counts = std::collections::BTreeMap::from([
            ("b".to_owned(), 2),
            ("a".to_owned(), 2),
            ("c".to_owned(), 9),
        ]);
        assert_eq!(top_counts(&counts, 2), "c (9), a (2)");
        assert_eq!(top_counts(&counts, 10), "c (9), a (2), b (2)");
        assert_eq!(top_counts(&std::collections::BTreeMap::new(), 3), "");
    }
}
