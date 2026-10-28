//! Process forensics: deleted executables, unlinked listeners and resource outliers.
//!
//! The Jenkins stage greps `ls -l /proc/*/exe`, `ss -tulpn` and `ps`. This stage walks `/proc`
//! natively for the executable check, which avoids shell globbing and keeps the output bounded.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

const PROC_ROOT: &str = "/proc";
const TOP_PROCESS_LINES: usize = 6;

/// `/proc` location inspected by this stage. Tests replace it with a temporary tree.
struct ProcessPaths {
    proc_root: PathBuf,
}

impl Default for ProcessPaths {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeletedProcess {
    pid: u32,
    target: String,
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, &ProcessPaths::default())
}

fn run_with_paths(ctx: &StageContext<'_>, paths: &ProcessPaths) -> StageReport {
    let mut report = StageReport::new(StageId::ProcessForensics);
    let mut timed_out = false;

    report.push_header("=== PROCESSES RUNNING FROM DELETED FILES ===");
    match deleted_processes(&paths.proc_root) {
        Ok(processes) if processes.is_empty() => {
            report.push_block("", "[+] No processes executing from deleted binaries.");
            report.note("no processes are executing from deleted binaries");
        }
        Ok(processes) => {
            let listing = processes
                .iter()
                .map(|process| format!("pid {} -> {}", process.pid, process.target))
                .collect::<Vec<_>>()
                .join("\n");
            report.push_block(
                &format!(
                    "[-] [MEDIUM] Found processes running from deleted files (could be pending restarts after updates, or fileless malware):\n{listing}"
                ),
                "",
            );
            report.finding(
                Severity::Medium,
                format!(
                    "{} process(es) are executing from deleted files",
                    processes.len()
                ),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.push_block("", "Skipped: /proc is not available.");
            report.finding(
                Severity::Low,
                "`/proc` is unavailable; processes running from deleted files could not be audited",
            );
        }
        Err(error) => {
            report.push_block("", &format!("Could not scan /proc: {error}"));
            report.finding(
                Severity::Medium,
                format!("could not scan /proc for deleted executables: {error}"),
            );
        }
    }

    report.push_header("=== UNLINKED NETWORK PROCESSES ===");
    if ctx.tool_exists("ss") {
        let sockets = ctx.run(Cmd::new("ss").args(["-tulpn"]).sudo(true));
        if sockets.timed_out {
            timed_out = true;
            report.push_block(&sockets.combined(), "(no output)");
            report.finding(Severity::Medium, "network socket enumeration timed out");
        } else {
            let unlinked = deleted_socket_lines(&sockets.stdout);
            if unlinked.is_empty() {
                report.push_block("", "[+] No deleted network listeners found.");
            } else {
                report.push_block(&unlinked, "");
                report.finding(
                    Severity::Medium,
                    format!(
                        "{} network socket(s) belong to processes backed by deleted files",
                        unlinked.lines().count()
                    ),
                );
            }
            if !sockets.success() {
                report.note(format!(
                    "ss -tulpn failed: {}",
                    first_lines(&sockets.combined(), 1)
                ));
            }
        }
    } else {
        report.push_block("", "Skipped: ss command not found.");
        report.note("`ss` was not found; unlinked network processes were not audited");
    }

    report.push_header("=== CPU/MEMORY ANOMALIES (TOP 5) ===");
    if ctx.tool_exists("ps") {
        let processes =
            ctx.run(Cmd::new("ps").args(["-eo", "pid,ppid,cmd,%cpu,%mem", "--sort=-%cpu"]));
        if processes.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "process resource listing timed out");
        } else {
            let top = top_processes(&processes.stdout);
            report.push_block(&top, "(no output)");
            if !processes.success() {
                report.note(format!(
                    "ps failed: {}",
                    first_lines(&processes.combined(), 1)
                ));
            }
        }
    } else {
        report.push_block("", "Skipped: ps command not found.");
        report.note("`ps` was not found; CPU/memory outliers were not listed");
    }

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        report.finish(None);
    }
    report
}

fn deleted_processes(proc_root: &Path) -> io::Result<Vec<DeletedProcess>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Ok(target) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let target = target.to_string_lossy();
        if target.contains(" (deleted)") {
            processes.push(DeletedProcess {
                pid,
                target: target.into_owned(),
            });
        }
    }
    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

fn deleted_socket_lines(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| line.contains(" (deleted)"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn top_processes(stdout: &str) -> String {
    stdout
        .lines()
        .take(TOP_PROCESS_LINES)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::audit::test_support::{FakeRunner, ok, stage_context, timed_out};
    use crate::config::test_config;

    const SS: &str = "ss -tulpn";
    const PS: &str = "ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu";

    fn run_with(runner: &FakeRunner, proc_root: &Path) -> StageReport {
        let cfg = test_config();
        let ui = crate::test_support::ui();
        let ctx = stage_context(&cfg, runner, &ui);
        run_with_paths(
            &ctx,
            &ProcessPaths {
                proc_root: proc_root.to_path_buf(),
            },
        )
    }

    fn proc_dir(dir: &TempDir) -> PathBuf {
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(&proc_root).unwrap();
        proc_root
    }

    #[test]
    fn deleted_executable_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let pid = proc_root.join("4242");
        std::fs::create_dir_all(&pid).unwrap();
        std::os::unix::fs::symlink("/tmp/evil (deleted)", pid.join("exe")).unwrap();

        let report = run_with(&FakeRunner::new(&[]), &proc_root);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("executing from deleted files"))
        );
        assert!(report.output.contains("pid 4242"));
    }

    #[test]
    fn live_executables_pass() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let pid = proc_root.join("1");
        std::fs::create_dir_all(&pid).unwrap();
        std::os::unix::fs::symlink("/usr/sbin/init", pid.join("exe")).unwrap();

        let report = run_with(&FakeRunner::new(&[]), &proc_root);
        assert!(
            report
                .output
                .contains("No processes executing from deleted binaries.")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.message.contains("executing from deleted files"))
        );
    }

    #[test]
    fn missing_proc_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_with(&FakeRunner::new(&[]), &dir.path().join("missing-proc"));
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("`/proc` is unavailable"))
        );
    }

    #[test]
    fn deleted_socket_line_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let runner = FakeRunner::new(&["ss"]).respond(
            SS,
            ok("tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"evil\",pid=9,fd=3)) (deleted)\n"),
        );
        let report = run_with(&runner, &proc_root);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("deleted files"))
        );
    }

    #[test]
    fn socket_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let runner = FakeRunner::new(&["ss"]).respond(SS, timed_out());
        let report = run_with(&runner, &proc_root);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("socket enumeration timed out"))
        );
    }

    #[test]
    fn top_processes_are_limited() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let output = "PID PPID CMD %CPU %MEM\n1 0 init 1.0 0.1\n2 1 worker 2.0 0.2\n3 1 worker 3.0 0.3\n4 1 worker 4.0 0.4\n5 1 worker 5.0 0.5\n6 1 worker 6.0 0.6\n7 1 worker 7.0 0.7\n";
        let runner = FakeRunner::new(&["ps"]).respond(PS, ok(output));
        let report = run_with(&runner, &proc_root);
        assert!(report.output.contains("CPU/MEMORY ANOMALIES"));
        assert!(!report.output.contains("7 1 worker"));
    }

    #[test]
    fn ps_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let runner = FakeRunner::new(&["ps"]).respond(PS, timed_out());
        let report = run_with(&runner, &proc_root);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("resource listing timed out"))
        );
    }

    #[test]
    fn missing_tools_are_noted() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir(&dir);
        let report = run_with(&FakeRunner::new(&[]), &proc_root);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("`ss` was not found"))
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("`ps` was not found"))
        );
    }
}
