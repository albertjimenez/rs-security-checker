//! Stage 2: Docker Security Audit.

use serde::Deserialize;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

/// Both the classic and the merged-/usr location are common; a container can mount either one.
const DOCKER_SOCKET_PATHS: [&str; 2] = ["/var/run/docker.sock", "/run/docker.sock"];

#[derive(Debug, Deserialize)]
struct Mount {
    #[serde(rename = "Source")]
    source: Option<String>,
    #[serde(rename = "Destination")]
    destination: Option<String>,
}

fn docker_socket_path(mount: &Mount) -> Option<&str> {
    [mount.source.as_deref(), mount.destination.as_deref()]
        .into_iter()
        .flatten()
        .find(|path| DOCKER_SOCKET_PATHS.contains(path))
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let mut report = StageReport::new(StageId::Docker);

    if !ctx.tool_exists("docker") {
        write_skipped(&mut report, "Skipped: docker command not found.");
        report.note("`docker` was not found; Docker audit skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let ps = ctx.run(Cmd::new("docker").args(["ps", "-q"]).sudo(true));
    if ps.dry_run {
        write_skipped(&mut report, "Dry-run: docker commands were not executed.");
        report.note("dry-run: Docker audit was not executed");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }
    if !ps.success() {
        let detail = first_lines(&ps.combined(), 2);
        let message = if detail.is_empty() {
            "Skipped: docker daemon unavailable.".to_owned()
        } else {
            format!("Skipped: docker daemon unavailable ({detail}).")
        };
        write_skipped(&mut report, &message);
        report.note(format!(
            "docker audit skipped: {}",
            if detail.is_empty() {
                ps.exit_description()
            } else {
                detail
            }
        ));
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let container_ids = parse_container_ids(&ps.stdout);
    if container_ids.is_empty() {
        report.note("no running containers were found");
    }

    let mut socket_mounts = Vec::new();
    let mut privileged_containers = Vec::new();

    for id in container_ids {
        let inspected = ctx.run(
            Cmd::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.Name}} {{.HostConfig.Privileged}}",
                    &id,
                ])
                .sudo(true),
        );
        if !inspected.success() {
            report.note(format!(
                "could not inspect container {id}: {}",
                first_lines(&inspected.combined(), 1)
            ));
            continue;
        }

        let line = inspected.stdout.lines().next().unwrap_or_default().trim();
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("unknown").to_owned();
        let privileged = parts.next().is_some_and(|value| value == "true");

        let mounts = ctx.run(
            Cmd::new("docker")
                .args(["inspect", "--format", "{{json .Mounts}}", &id])
                .sudo(true),
        );
        let mut socket_path = None;
        if mounts.success() {
            match serde_json::from_str::<Vec<Mount>>(mounts.stdout.trim()) {
                Ok(mounts) => {
                    socket_path = mounts
                        .iter()
                        .find_map(docker_socket_path)
                        .map(str::to_owned);
                }
                Err(error) => report.note(format!(
                    "could not parse mount list for container {name}: {error}"
                )),
            }
        } else {
            report.note(format!(
                "could not inspect mounts for container {name}: {}",
                first_lines(&mounts.combined(), 1)
            ));
        }

        if let Some(socket_path) = socket_path {
            report.finding(
                Severity::High,
                format!("container {name} mounts the Docker socket ({socket_path})"),
            );
            socket_mounts.push((name.clone(), socket_path));
        }
        if privileged {
            privileged_containers.push(name.clone());
            report.finding(
                Severity::High,
                format!("container {name} is running with Privileged=true"),
            );
        }
    }

    report.push_header("=== DOCKER SOCKET MOUNT CHECK ===");
    if socket_mounts.is_empty() {
        report.push_block("", "No containers mount docker.sock.");
    } else {
        for (name, path) in &socket_mounts {
            report
                .output
                .push_str(&format!("{name}: MOUNTED_DOCKER_SOCK (source={path})\n"));
        }
    }

    report.push_header("=== PRIVILEGED CONTAINER CHECK ===");
    if privileged_containers.is_empty() {
        report.push_block("", "No privileged containers running.");
    } else {
        for name in &privileged_containers {
            report
                .output
                .push_str(&format!("{name}: Privileged=true\n"));
        }
    }

    report.finish(None);
    report
}

fn write_skipped(report: &mut StageReport, message: &str) {
    report.push_header("=== DOCKER SOCKET MOUNT CHECK ===");
    report.push_block("", message);
    report.push_header("=== PRIVILEGED CONTAINER CHECK ===");
    report.push_block("", message);
}

fn parse_container_ids(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            // Docker emits short or full hex ids. Reject anything else before passing it as argv.
            line.len() >= 4 && line.chars().all(|c| c.is_ascii_hexdigit())
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{FakeRunner, dry, exit, ok, run_stage};
    use crate::config::test_config;

    const INSPECT: &str = "docker inspect --format {{.Name}} {{.HostConfig.Privileged}}";
    const MOUNTS: &str = "docker inspect --format {{json .Mounts}}";

    fn run(runner: &FakeRunner) -> StageReport {
        run_stage(StageId::Docker, runner, &test_config())
    }

    #[test]
    fn parses_only_hex_container_ids() {
        let ids = parse_container_ids("abc123\nnot-an-id\n\nfedcba\n");
        assert_eq!(ids, vec!["abc123", "fedcba"]);
    }

    #[test]
    fn missing_docker_skips_the_stage() {
        let report = run(&FakeRunner::new(&[]));
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(report.notes.iter().any(|note| note.contains("docker")));
    }

    #[test]
    fn dry_run_skips_the_stage() {
        let runner = FakeRunner::new(&["docker"]).respond("docker ps -q", dry());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(report.notes.iter().any(|note| note.contains("dry-run")));
    }

    #[test]
    fn daemon_failure_is_reported_without_details() {
        let runner = FakeRunner::new(&["docker"]).respond("docker ps -q", exit(1, ""));
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(report.output.contains("docker daemon unavailable"));
    }

    #[test]
    fn daemon_failure_includes_stderr_detail() {
        let runner = FakeRunner::new(&["docker"]).respond(
            "docker ps -q",
            exit(1, "Cannot connect to the Docker daemon"),
        );
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("Cannot connect"))
        );
    }

    #[test]
    fn no_containers_passes() {
        let report = run(&FakeRunner::new(&["docker"]));
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("no running containers"))
        );
    }

    #[test]
    fn socket_mount_is_high_severity() {
        let runner = FakeRunner::new(&["docker"])
            .respond("docker ps -q", ok("abc123\n"))
            .respond(&format!("{INSPECT} abc123"), ok("/web false\n"))
            .respond(
                &format!("{MOUNTS} abc123"),
                ok(r#"[{"Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock"}]"#),
            );
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(report.output.contains("MOUNTED_DOCKER_SOCK"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("mounts the Docker socket"))
        );
    }

    #[test]
    fn privileged_container_is_high_severity() {
        let runner = FakeRunner::new(&["docker"])
            .respond("docker ps -q", ok("abc123\n"))
            .respond(&format!("{INSPECT} abc123"), ok("/db true\n"))
            .respond(&format!("{MOUNTS} abc123"), ok("[]"));
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(report.output.contains("Privileged=true"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("Privileged=true"))
        );
    }

    #[test]
    fn inspect_failure_is_noted_and_skipped() {
        let runner = FakeRunner::new(&["docker"])
            .respond("docker ps -q", ok("abc123\n"))
            .respond(&format!("{INSPECT} abc123"), exit(1, "no such container"));
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("could not inspect container"))
        );
    }

    #[test]
    fn mount_inspect_failure_is_noted() {
        let runner = FakeRunner::new(&["docker"])
            .respond("docker ps -q", ok("abc123\n"))
            .respond(&format!("{INSPECT} abc123"), ok("/web false\n"))
            .respond(&format!("{MOUNTS} abc123"), exit(1, "no such container"));
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("could not inspect mounts"))
        );
    }

    #[test]
    fn malformed_mount_json_is_noted() {
        let runner = FakeRunner::new(&["docker"])
            .respond("docker ps -q", ok("abc123\n"))
            .respond(&format!("{INSPECT} abc123"), ok("/web false\n"))
            .respond(&format!("{MOUNTS} abc123"), ok("not-json"));
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("could not parse mount list"))
        );
    }
}
