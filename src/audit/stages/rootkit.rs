//! Stage 5: Rootkit Audits.

use std::sync::LazyLock;

use regex::Regex;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

const EXCLUDE_SUBSTRINGS: [&str; 7] = [
    "/usr/lib/python3/",
    "/usr/lib/jvm/",
    "/usr/lib/ruby/",
    "/usr/lib/node_modules/",
    "/usr/lib/libreoffice/",
    "PACKET SNIFFER(/usr/sbin/NetworkManager",
    "infected ports: 4000 45454",
];

static EXCLUDE_REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"defmt-[0-9.]*/src/impls/core_").expect("valid defmt exclusion regex"),
        Regex::new(r"/tmp/yarn--[0-9]+-[0-9.]+").expect("valid yarn exclusion regex"),
    ]
});

pub fn filter_chkrootkit(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            !EXCLUDE_SUBSTRINGS
                .iter()
                .any(|needle| line.contains(needle))
        })
        .filter(|line| !EXCLUDE_REGEXES.iter().any(|regex| regex.is_match(line)))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let mut report = StageReport::new(StageId::Rootkit);
    let chkrootkit_available = ctx.tool_exists("chkrootkit");
    let rkhunter_available = ctx.tool_exists("rkhunter");

    if !chkrootkit_available && !rkhunter_available {
        report.push_header("--- CHKROOTKIT ---");
        report.push_block("", "Skipped: chkrootkit command not found.");
        report.push_header("--- RKHUNTER ---");
        report.push_block("", "Skipped: rkhunter command not found.");
        report.note("neither `chkrootkit` nor `rkhunter` was found; rootkit audit skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let mut timed_out = false;

    report.push_header("--- CHKROOTKIT ---");
    if chkrootkit_available {
        let output = ctx.run(Cmd::new("chkrootkit").arg("-q").sudo(true));
        if output.dry_run {
            report.push_block(&output.stdout, "(no output)");
        } else if output.timed_out {
            timed_out = true;
            report.push_block(&output.combined(), "(no output)");
            report.finding(Severity::High, "chkrootkit timed out");
        } else if output.error.is_some() {
            report.push_block(&output.combined(), "(no output)");
            report.finding(
                Severity::Medium,
                format!(
                    "chkrootkit could not be executed: {}",
                    output.exit_description()
                ),
            );
        } else {
            let filtered = filter_chkrootkit(&output.combined());
            report.push_block(&filtered, "(no output)");
            if !filtered.is_empty() {
                report.finding(
                    Severity::High,
                    format!(
                        "chkrootkit reported suspicious output: {}",
                        first_lines(&filtered, 3)
                    ),
                );
            } else if !output.success() {
                report.note(format!(
                    "chkrootkit exited with {}; all output was filtered as known-benign",
                    output.exit_description()
                ));
            }
        }
    } else {
        report.push_block("", "Skipped: chkrootkit command not found.");
        report.note("`chkrootkit` was not found");
    }

    report.push_header("--- RKHUNTER ---");
    if rkhunter_available {
        let output = ctx.run(
            Cmd::new("rkhunter")
                .args(["--cronjob", "--report-warnings-only", "--skip-keypress"])
                .sudo(true),
        );
        if output.dry_run {
            report.push_block(&output.stdout, "(no output)");
        } else if output.timed_out {
            timed_out = true;
            report.push_block(&output.combined(), "(no output)");
            report.finding(Severity::High, "rkhunter timed out");
        } else if output.error.is_some() {
            report.push_block(&output.combined(), "(no output)");
            report.finding(
                Severity::Medium,
                format!(
                    "rkhunter could not be executed: {}",
                    output.exit_description()
                ),
            );
        } else {
            let combined = output.combined();
            report.push_block(&combined, "(no output)");
            if !combined.trim().is_empty() {
                report.finding(
                    Severity::High,
                    format!("rkhunter reported warnings: {}", first_lines(&combined, 3)),
                );
            }
        }
    } else {
        report.push_block("", "Skipped: rkhunter command not found.");
        report.note("`rkhunter` was not found");
    }

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        if ctx.cfg.dry_run {
            report.note("dry-run: rootkit tools were not executed");
        }
        report.finish(None);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{
        FakeRunner, command_error, dry, exit, ok, run_stage, timed_out,
    };
    use crate::config::test_config;

    const CHKROOTKIT: &str = "chkrootkit -q";
    const RKHUNTER: &str = "rkhunter --cronjob --report-warnings-only --skip-keypress";

    fn run(runner: &FakeRunner) -> StageReport {
        run_stage(StageId::Rootkit, runner, &test_config())
    }

    #[test]
    fn filters_known_benign_chkrootkit_noise() {
        let input = "\
/usr/lib/python3/foo: PACKET SNIFFER
PACKET SNIFFER(/usr/sbin/NetworkManager)
defmt-0.3/src/impls/core_output
/tmp/yarn--123-1.2.3/bin/node
INFECTED: /tmp/evil
";
        let filtered = filter_chkrootkit(input);
        assert_eq!(filtered, "INFECTED: /tmp/evil");
    }

    #[test]
    fn filters_empty_lines_and_other_known_noise() {
        let input = "
/usr/lib/jvm/foo: nothing
infected ports: 4000 45454
/usr/lib/ruby/bar
/usr/lib/node_modules/baz
/usr/lib/libreoffice/qux
";
        assert!(filter_chkrootkit(input).is_empty());
    }

    #[test]
    fn neither_tool_skips_the_stage() {
        let report = run(&FakeRunner::new(&[]));
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("neither `chkrootkit` nor `rkhunter`"))
        );
    }

    #[test]
    fn only_chkrootkit_dry_run_is_noted() {
        let runner = FakeRunner::new(&["chkrootkit"]).respond(CHKROOTKIT, dry());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.notes.iter().any(|note| note.contains("rkhunter")));
    }

    #[test]
    fn chkrootkit_timeout_is_high_severity() {
        let runner = FakeRunner::new(&["chkrootkit"]).respond(CHKROOTKIT, timed_out());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert_eq!(report.highest_severity(), Severity::High);
    }

    #[test]
    fn chkrootkit_spawn_error_is_a_medium_finding() {
        let runner =
            FakeRunner::new(&["chkrootkit"]).respond(CHKROOTKIT, command_error("spawn failed"));
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("could not be executed"))
        );
    }

    #[test]
    fn chkrootkit_suspicious_output_is_high_severity() {
        let runner =
            FakeRunner::new(&["chkrootkit"]).respond(CHKROOTKIT, ok("INFECTED: /tmp/evil\n"));
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("suspicious output"))
        );
    }

    #[test]
    fn chkrootkit_benign_output_on_failure_is_noted() {
        let runner = FakeRunner::new(&["chkrootkit"])
            .respond(CHKROOTKIT, exit(1, "/usr/lib/python3/foo: PACKET SNIFFER"));
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("known-benign"))
        );
    }

    #[test]
    fn only_rkhunter_dry_run_is_noted() {
        let runner = FakeRunner::new(&["rkhunter"]).respond(RKHUNTER, dry());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.notes.iter().any(|note| note.contains("chkrootkit")));
    }

    #[test]
    fn rkhunter_timeout_is_high_severity() {
        let runner = FakeRunner::new(&["rkhunter"]).respond(RKHUNTER, timed_out());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert_eq!(report.highest_severity(), Severity::High);
    }

    #[test]
    fn rkhunter_spawn_error_is_a_medium_finding() {
        let runner =
            FakeRunner::new(&["rkhunter"]).respond(RKHUNTER, command_error("spawn failed"));
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("could not be executed"))
        );
    }

    #[test]
    fn rkhunter_warnings_are_high_severity() {
        let runner =
            FakeRunner::new(&["rkhunter"]).respond(RKHUNTER, ok("Warning: hidden file /tmp/x\n"));
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("rkhunter reported warnings"))
        );
    }

    #[test]
    fn both_tools_clean_passes() {
        let report = run(&FakeRunner::new(&["chkrootkit", "rkhunter"]));
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.findings.is_empty());
    }
}
