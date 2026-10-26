//! Deterministic command runner and fixtures shared by the stage tests.
//!
//! The production runner spawns real processes. Stage tests use [`FakeRunner`] instead so every
//! branch (missing tool, timeout, malformed output, ...) can be exercised without root or Debian.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::exec::{Cmd, CommandOutput, CommandRunner};
use crate::report::{Severity, StageId, StageReport};
use crate::ui::Ui;

use super::{StageContext, execute};

fn base(program: &str) -> CommandOutput {
    CommandOutput {
        program: program.to_owned(),
        args: Vec::new(),
        code: Some(0),
        signal: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        error: None,
        dry_run: false,
    }
}

pub(crate) fn ok(stdout: impl Into<String>) -> CommandOutput {
    let mut output = base("test");
    output.stdout = stdout.into();
    output
}

pub(crate) fn exit(code: i32, stderr: impl Into<String>) -> CommandOutput {
    let mut output = base("test");
    output.code = Some(code);
    output.stderr = stderr.into();
    output
}

pub(crate) fn timed_out() -> CommandOutput {
    let mut output = base("test");
    output.code = None;
    output.timed_out = true;
    output
}

pub(crate) fn command_error(message: impl Into<String>) -> CommandOutput {
    let mut output = base("test");
    output.code = None;
    output.error = Some(message.into());
    output
}

pub(crate) fn dry() -> CommandOutput {
    let mut output = base("test");
    output.dry_run = true;
    output.stdout = "[dry-run]\n".to_owned();
    output
}

/// A command runner that returns pre-programmed output and records every invocation.
pub(crate) struct FakeRunner {
    tools: BTreeSet<String>,
    responses: Mutex<HashMap<String, VecDeque<CommandOutput>>>,
    default: CommandOutput,
    calls: Mutex<Vec<String>>,
}

impl FakeRunner {
    pub(crate) fn new(tools: &[&str]) -> Self {
        Self {
            tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            responses: Mutex::new(HashMap::new()),
            default: ok(""),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Queue a response for a command. Repeated calls queue responses in order.
    pub(crate) fn respond(self, command: &str, output: CommandOutput) -> Self {
        self.responses
            .lock()
            .expect("fake runner responses lock poisoned")
            .entry(command.to_owned())
            .or_default()
            .push_back(output);
        self
    }

    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("fake runner calls lock poisoned")
            .clone()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, cmd: &Cmd, _deadline: Instant) -> CommandOutput {
        let key = command_key(cmd);
        self.calls
            .lock()
            .expect("fake runner calls lock poisoned")
            .push(key.clone());
        let default = self.default.clone();
        self.responses
            .lock()
            .expect("fake runner responses lock poisoned")
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .unwrap_or(default)
    }

    fn tool_exists(&self, program: &str) -> bool {
        self.tools.contains(program)
    }
}

fn command_key(cmd: &Cmd) -> String {
    let mut key = cmd.program().to_owned();
    for arg in cmd.arguments() {
        key.push(' ');
        key.push_str(&arg.to_string_lossy());
    }
    key
}

pub(crate) fn stage_context<'a>(
    cfg: &'a crate::config::Config,
    runner: &'a FakeRunner,
    ui: &'a Ui,
) -> StageContext<'a> {
    StageContext {
        cfg,
        runner,
        ui,
        deadline: Instant::now() + Duration::from_secs(60),
    }
}

/// Build a context whose deadline has already passed, to exercise the skip path.
pub(crate) fn expired_context<'a>(
    cfg: &'a crate::config::Config,
    runner: &'a FakeRunner,
    ui: &'a Ui,
) -> StageContext<'a> {
    StageContext {
        cfg,
        runner,
        ui,
        deadline: Instant::now() - Duration::from_secs(1),
    }
}

pub(crate) fn run_stage(
    stage: StageId,
    runner: &FakeRunner,
    cfg: &crate::config::Config,
) -> StageReport {
    let ui = crate::test_support::ui();
    let ctx = stage_context(cfg, runner, &ui);
    execute(stage, &ctx)
}

/// Write `contents` to `path`, creating parent directories as needed.
pub(crate) fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

/// Run a stage against a single temporary log/config file.
pub(crate) fn run_with_file(
    text: &str,
    name: &str,
    run: impl FnOnce(&StageContext<'_>, &PathBuf) -> StageReport,
) -> StageReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    write(&path, text);
    let runner = FakeRunner::new(&[]);
    let ui = crate::test_support::ui();
    let cfg = crate::config::test_config();
    let ctx = stage_context(&cfg, &runner, &ui);
    run(&ctx, &path)
}

/// Whether the report contains a finding with this severity whose message includes `needle`.
pub(crate) fn finding(report: &StageReport, severity: Severity, needle: &str) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.severity == severity && finding.message.contains(needle))
}

/// Whether any finding, at any severity, includes `needle`.
pub(crate) fn finding_message(report: &StageReport, needle: &str) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.message.contains(needle))
}

/// Whether any report note includes `needle`.
pub(crate) fn note(report: &StageReport, needle: &str) -> bool {
    report.notes.iter().any(|note| note.contains(needle))
}
