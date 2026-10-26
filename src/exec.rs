//! Safe process execution.
//!
//! Every command is executed with an explicit `argv` (never through a shell), a fixed `PATH`,
//! a null stdin, a per-command/global deadline and a bounded output buffer. Commands that need
//! root use `sudo -n --` so a missing password can never hang the pipeline.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::ui::Ui;

#[cfg(unix)]
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static CHILD_GROUPS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Fixed lookup path. It deliberately excludes the caller's `PATH` so a compromised
/// environment cannot shadow audit tools such as `docker` or `clamscan`.
pub use crate::constants::FIXED_PATH;

/// Environment variables that can inject code into child processes. They are removed before
/// spawning audit tools; the fixed `PATH` and locale are set explicitly afterwards.
const DANGEROUS_ENV: [&str; 19] = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "CDPATH",
    "IFS",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5LIB",
    "RUBYOPT",
    "NODE_OPTIONS",
    "NODE_PATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum SudoMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone)]
pub struct Cmd {
    program: String,
    args: Vec<OsString>,
    sudo: bool,
    env: Vec<(OsString, OsString)>,
    timeout: Option<Duration>,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            sudo: false,
            env: Vec::new(),
            timeout: None,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    pub fn sudo(mut self, sudo: bool) -> Self {
        self.sudo = sudo;
        self
    }

    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Override the per-command timeout. The global deadline still wins.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn arguments(&self) -> impl Iterator<Item = &OsStr> {
        self.args.iter().map(OsString::as_os_str)
    }

    /// Human-readable command line used in logs and findings.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn display_command(&self) -> String {
        let args = self
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        render_command(&self.program, &args)
    }
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub program: String,
    pub args: Vec<String>,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub error: Option<String>,
    pub dry_run: bool,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        // Dry-run commands are simulated as successful so the audit can exercise every stage
        // without producing false failures.
        self.dry_run || (!self.timed_out && self.error.is_none() && self.code == Some(0))
    }

    pub fn exit_description(&self) -> String {
        if self.dry_run {
            return "dry-run".to_owned();
        }
        if self.timed_out {
            return "timed out".to_owned();
        }
        if let Some(error) = &self.error {
            return error.clone();
        }
        match (self.code, self.signal) {
            (Some(code), _) => format!("exit {code}"),
            (None, Some(signal)) => format!("signal {signal}"),
            _ => "unknown status".to_owned(),
        }
    }

    pub fn combined(&self) -> Cow<'_, str> {
        if self.stderr.trim().is_empty() {
            return Cow::Borrowed(&self.stdout);
        }
        if self.stdout.trim().is_empty() {
            return Cow::Borrowed(&self.stderr);
        }
        let mut combined = String::with_capacity(self.stdout.len() + self.stderr.len() + 1);
        combined.push_str(&self.stdout);
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&self.stderr);
        Cow::Owned(combined)
    }

    pub fn display_command(&self) -> String {
        render_command(&self.program, &self.args)
    }

    pub(crate) fn failed(message: impl Into<String>, program: &str, args: &[String]) -> Self {
        Self {
            program: program.to_owned(),
            args: args.to_vec(),
            code: None,
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(message.into()),
            dry_run: false,
        }
    }

    pub(crate) fn dry_run(program: &str, args: &[String]) -> Self {
        Self {
            program: program.to_owned(),
            args: args.to_vec(),
            code: Some(0),
            signal: None,
            stdout: format!(
                "[dry-run] would execute: {}\n",
                render_command(program, args)
            ),
            stderr: String::new(),
            timed_out: false,
            error: None,
            dry_run: true,
        }
    }
}

fn render_command<S: AsRef<str>>(program: &str, args: &[S]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_escape(program));
    parts.extend(args.iter().map(|arg| shell_escape(arg.as_ref())));
    parts.join(" ")
}

/// Abstraction over process execution so audit stages can be tested with deterministic output.
///
/// `Sync` is required because the lightweight analysis stages share one runner across threads.
pub trait CommandRunner: Sync {
    fn run(&self, cmd: &Cmd, deadline: Instant) -> CommandOutput;
    fn tool_exists(&self, program: &str) -> bool;
}

pub struct Runner {
    sudo_mode: SudoMode,
    sudo_available: bool,
    is_root: bool,
    dry_run: bool,
    default_timeout: Option<Duration>,
    max_output_bytes: usize,
    ui: Ui,
}

impl Runner {
    pub fn new(
        sudo_mode: SudoMode,
        dry_run: bool,
        default_timeout: Option<Duration>,
        max_output_bytes: usize,
        ui: Ui,
    ) -> Self {
        Self {
            sudo_mode,
            sudo_available: find_in_path("sudo").is_some(),
            is_root: nix::unistd::Uid::effective().is_root(),
            dry_run,
            default_timeout,
            max_output_bytes: max_output_bytes.max(1024),
            ui,
        }
    }

    pub fn sudo_available(&self) -> bool {
        self.sudo_available
    }

    pub fn is_root(&self) -> bool {
        self.is_root
    }

    /// Whether commands marked `sudo(true)` will actually be prefixed with sudo.
    pub fn uses_sudo(&self) -> bool {
        match self.sudo_mode {
            SudoMode::Never => false,
            SudoMode::Always => true,
            SudoMode::Auto => !self.is_root && self.sudo_available,
        }
    }
}

impl CommandRunner for Runner {
    fn run(&self, cmd: &Cmd, deadline: Instant) -> CommandOutput {
        let program = cmd.program.as_str();

        let mut argv: Vec<OsString> = Vec::with_capacity(cmd.args.len() + 4);
        let use_sudo = cmd.sudo && self.uses_sudo();
        if use_sudo {
            argv.push(OsString::from("sudo"));
            argv.push(OsString::from("-n"));
            argv.push(OsString::from("--"));
        }
        argv.push(OsString::from(program));
        argv.extend(cmd.args.iter().cloned());

        let display_args: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let display_program = display_args.first().cloned().unwrap_or_default();
        let display_rest = display_args
            .get(1..)
            .map(<[String]>::to_vec)
            .unwrap_or_default();
        let display = render_command(&display_program, &display_rest);

        if self.dry_run {
            let out = CommandOutput::dry_run(&display_program, &display_rest);
            self.ui.command_line(&display);
            return out;
        }

        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            let out =
                CommandOutput::failed("global timeout reached", &display_program, &display_rest);
            self.ui.command_line(&display);
            self.ui
                .warn(format!("skipped `{program}`: global timeout reached"));
            return out;
        };

        let configured_timeout = match (cmd.timeout, self.default_timeout) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let timeout = configured_timeout.map_or(remaining, |t| t.min(remaining));

        // Resolve both the command and `sudo` through the fixed PATH. Spawning by bare name would
        // let the caller's `PATH` shadow the audit tools even though `tool_exists` checks
        // `FIXED_PATH`; `execvp` uses the caller's environment, not the child's.
        //
        // Every spawn failure is reported the same way: a failed output, the command line (unless
        // it was already announced before spawning) and a debug line with the reason.
        let spawn_failure = |message: String, announce: bool| {
            let out = CommandOutput::failed(message, &display_program, &display_rest);
            if announce {
                self.ui.command_line(&display);
            }
            self.ui.debug(out.exit_description());
            out
        };
        let Some(executable) = find_in_path(program) else {
            return spawn_failure(
                format!(
                    "failed to spawn `{display_program}`: `{program}` was not found in the fixed PATH"
                ),
                true,
            );
        };
        let sudo_executable = if use_sudo {
            let Some(path) = find_in_path("sudo") else {
                return spawn_failure(
                    format!(
                        "failed to spawn `{display_program}`: `sudo` was not found in the fixed PATH"
                    ),
                    true,
                );
            };
            Some(path)
        } else {
            None
        };

        let mut spawn_argv: Vec<OsString> = Vec::with_capacity(argv.len());
        if let Some(sudo) = sudo_executable {
            spawn_argv.push(sudo.into_os_string());
            spawn_argv.push(OsString::from("-n"));
            spawn_argv.push(OsString::from("--"));
        }
        spawn_argv.push(executable.into_os_string());
        spawn_argv.extend(cmd.args.iter().cloned());

        let mut command = Command::new(&spawn_argv[0]);
        command
            .args(&spawn_argv[1..])
            .env("PATH", FIXED_PATH)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in DANGEROUS_ENV {
            command.env_remove(key);
        }
        for (key, value) in &cmd.env {
            command.env(key, value);
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        self.ui.command_line(&display);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(source) => {
                return spawn_failure(
                    format!("failed to spawn `{display_program}`: {source}"),
                    false,
                );
            }
        };

        let child_pid = child.id();
        #[cfg(unix)]
        {
            if let Ok(mut groups) = CHILD_GROUPS.lock() {
                groups.push(child_pid);
            }
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let max_bytes = self.max_output_bytes;

        let (stdout_bytes, stderr_bytes, status, timed_out) = thread::scope(|scope| {
            let stdout_handle = stdout.map(|pipe| scope.spawn(move || drain(pipe, max_bytes)));
            let stderr_handle = stderr.map(|pipe| scope.spawn(move || drain(pipe, max_bytes)));

            let wait_deadline = Instant::now() + timeout;
            let (status, timed_out) = wait_with_timeout(&mut child, wait_deadline, child_pid);

            let (stdout_bytes, stdout_truncated) = stdout_handle
                .and_then(|handle| handle.join().ok())
                .unwrap_or_default();
            let (stderr_bytes, stderr_truncated) = stderr_handle
                .and_then(|handle| handle.join().ok())
                .unwrap_or_default();

            (
                (stdout_bytes, stdout_truncated),
                (stderr_bytes, stderr_truncated),
                status,
                timed_out,
            )
        });

        let (mut stdout, stdout_truncated) = stdout_bytes;
        let (mut stderr, stderr_truncated) = stderr_bytes;
        if stdout_truncated {
            let _ = write!(
                stdout,
                "\n[output truncated at {} bytes]\n",
                self.max_output_bytes
            );
        }
        if stderr_truncated {
            let _ = write!(
                stderr,
                "\n[output truncated at {} bytes]\n",
                self.max_output_bytes
            );
        }

        #[cfg(unix)]
        {
            if let Ok(mut groups) = CHILD_GROUPS.lock() {
                groups.retain(|pid| *pid != child_pid);
            }
        }
        let signal = status.and_then(|s| exit_signal(&s));
        let code = status.and_then(|s| s.code());
        let out = CommandOutput {
            program: display_program,
            args: display_rest,
            code,
            signal,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            timed_out,
            error: None,
            dry_run: false,
        };

        if timed_out {
            self.ui.warn(format!(
                "`{}` timed out after {:?}",
                out.display_command(),
                timeout
            ));
        } else if !out.success() {
            self.ui.debug(format!(
                "`{}` {}",
                out.display_command(),
                out.exit_description()
            ));
            if !out.stderr.trim().is_empty() {
                let preview = out.stderr.lines().take(5).collect::<Vec<_>>().join("\n");
                self.ui.debug(preview);
            }
        }

        out
    }

    fn tool_exists(&self, program: &str) -> bool {
        find_in_path(program).is_some()
    }
}

/// Find an executable using the fixed lookup path, never the inherited `PATH`.
pub fn find_in_path(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let path = Path::new(program);
        return is_executable(path).then(|| path.to_path_buf());
    }
    std::env::split_paths(FIXED_PATH)
        .map(|dir| dir.join(program))
        .find(|path| is_executable(path))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn wait_with_timeout(
    child: &mut Child,
    deadline: Instant,
    pgid: u32,
) -> (Option<ExitStatus>, bool) {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (Some(status), false),
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate(child, pgid);
                    return (child.wait().ok(), true);
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                terminate(child, pgid);
                return (child.wait().ok(), false);
            }
        }
    }
}

fn terminate(child: &mut Child, pgid: u32) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill, killpg};
        use nix::unistd::Pid;

        let group = Pid::from_raw(pgid as i32);
        let _ = killpg(group, Signal::SIGTERM);
        let grace = Instant::now() + Duration::from_secs(2);
        while Instant::now() < grace {
            // Reap the leader if it already exited, but keep waiting for group members that
            // ignored SIGTERM. Signal 0 probes the group without delivering a signal.
            let _ = child.try_wait();
            if kill(Pid::from_raw(-(pgid as i32)), None).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = killpg(group, Signal::SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
        let _ = child.kill();
    }
}

fn exit_signal(status: &ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

/// Read a pipe to EOF while keeping at most `limit` bytes. The pipe is always drained so the
/// child can never block on a full pipe buffer.
fn drain(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < limit {
                    let take = (limit - kept.len()).min(n);
                    kept.extend_from_slice(&buffer[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (kept, truncated)
}

pub fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+%".contains(c))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::*;

    fn ui() -> Ui {
        Ui::new(crate::ui::ColorMode::Never, true, false, false)
    }

    fn runner(dry_run: bool, max_output_bytes: usize) -> Runner {
        Runner::new(
            SudoMode::Never,
            dry_run,
            Some(Duration::from_secs(5)),
            max_output_bytes,
            ui(),
        )
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn output(stdout: &str, stderr: &str) -> CommandOutput {
        CommandOutput {
            program: "demo".into(),
            args: vec!["arg".into()],
            code: Some(0),
            signal: None,
            stdout: stdout.into(),
            stderr: stderr.into(),
            timed_out: false,
            error: None,
            dry_run: false,
        }
    }

    #[test]
    fn shell_escape_quotes_specials() {
        assert_eq!(shell_escape(""), "''");
        assert_eq!(shell_escape("docker"), "docker");
        assert_eq!(shell_escape("/var/lib/docker"), "/var/lib/docker");
        assert_eq!(shell_escape("a b"), "'a b'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn find_in_path_ignores_inherited_path() {
        // `sh` is always present in the fixed path on supported Unix hosts.
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("/definitely/not/a/real/tool").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn find_in_path_checks_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        fs::write(&path, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_in_path(path.to_str().unwrap()), Some(path.clone()));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(find_in_path(path.to_str().unwrap()).is_none());
        assert!(find_in_path(dir.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn drain_keeps_limit_and_drains() {
        let data = vec![b'x'; 10_000];
        let (kept, truncated) = drain(Cursor::new(data), 100);
        assert_eq!(kept.len(), 100);
        assert!(truncated);
    }

    #[test]
    fn drain_handles_short_empty_and_failing_reads() {
        let (kept, truncated) = drain(Cursor::new(b"abc".to_vec()), 100);
        assert_eq!(kept, b"abc");
        assert!(!truncated);

        let (kept, truncated) = drain(Cursor::new(Vec::new()), 100);
        assert!(kept.is_empty());
        assert!(!truncated);

        struct Flaky {
            calls: usize,
        }

        impl Read for Flaky {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                match self.calls {
                    1 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                    2 => {
                        buffer[..1].copy_from_slice(b"z");
                        Ok(1)
                    }
                    _ => Ok(0),
                }
            }
        }

        let (kept, truncated) = drain(Flaky { calls: 0 }, 10);
        assert_eq!(kept, b"z");
        assert!(!truncated);
    }

    #[test]
    fn command_builder_and_display() {
        let cmd = Cmd::new("echo")
            .arg("a")
            .args(["b", "c"])
            .env("DEMO", "1")
            .sudo(true)
            .timeout(Duration::from_secs(1));
        assert_eq!(cmd.program(), "echo");
        assert_eq!(
            cmd.arguments()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert_eq!(cmd.display_command(), "echo a b c");
    }

    #[test]
    fn command_output_success_rules() {
        let base = output("", "");
        assert!(base.success());

        let mut timed_out = base.clone();
        timed_out.timed_out = true;
        assert!(!timed_out.success());

        let mut failed = base.clone();
        failed.code = Some(1);
        assert!(!failed.success());

        let mut errored = base.clone();
        errored.error = Some("spawn failed".into());
        assert!(!errored.success());

        let mut dry = base;
        dry.dry_run = true;
        assert!(dry.success());
    }

    #[test]
    fn command_output_combines_streams_without_needless_copies() {
        let stdout_only = output("out\n", "");
        assert!(matches!(stdout_only.combined(), Cow::Borrowed(_)));
        assert_eq!(stdout_only.combined(), "out\n");

        let stderr_only = output("", "err\n");
        assert!(matches!(stderr_only.combined(), Cow::Borrowed(_)));
        assert_eq!(stderr_only.combined(), "err\n");

        let both = output("out", "err");
        assert!(matches!(both.combined(), Cow::Owned(_)));
        assert_eq!(both.combined(), "out\nerr");

        let newline = output("out\n", "err");
        assert_eq!(newline.combined(), "out\nerr");

        let empty = output("", "");
        assert_eq!(empty.combined(), "");
    }

    #[test]
    fn command_output_descriptions_and_display() {
        let mut out = output("", "");
        assert_eq!(out.exit_description(), "exit 0");
        assert_eq!(out.display_command(), "demo arg");

        out.dry_run = true;
        assert_eq!(out.exit_description(), "dry-run");

        out.dry_run = false;
        out.timed_out = true;
        assert_eq!(out.exit_description(), "timed out");

        out.timed_out = false;
        out.error = Some("boom".into());
        assert_eq!(out.exit_description(), "boom");

        out.error = None;
        out.code = None;
        out.signal = Some(9);
        assert_eq!(out.exit_description(), "signal 9");

        out.signal = None;
        assert_eq!(out.exit_description(), "unknown status");

        let dry = CommandOutput::dry_run("echo", &["hello world".to_owned()]);
        assert!(dry.dry_run);
        assert!(dry.stdout.contains("echo 'hello world'"));
    }

    #[test]
    fn dry_run_never_spawns_a_process() {
        let runner = runner(true, 1024);
        let out = runner.run(&Cmd::new("echo").arg("hi"), deadline());
        assert!(out.dry_run);
        assert!(out.success());
        assert!(out.stdout.contains("[dry-run] would execute: echo hi"));
    }

    #[test]
    fn global_deadline_prevents_execution() {
        let runner = runner(false, 1024);
        let out = runner.run(
            &Cmd::new("sh").args(["-c", "true"]),
            Instant::now() - Duration::from_secs(1),
        );
        assert!(!out.success());
        assert_eq!(out.error.as_deref(), Some("global timeout reached"),);
    }

    #[test]
    fn executes_commands_and_captures_stdout() {
        let runner = runner(false, 1024);
        let out = runner.run(&Cmd::new("sh").args(["-c", "printf hello"]), deadline());
        assert!(out.success());
        assert_eq!(out.stdout, "hello");
        assert_eq!(out.code, Some(0));
        assert!(!out.dry_run);
    }

    #[test]
    fn captures_stderr_and_non_zero_exit_codes() {
        let runner = runner(false, 1024);
        let out = runner.run(
            &Cmd::new("sh").args(["-c", "printf err >&2; exit 3"]),
            deadline(),
        );
        assert!(!out.success());
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stderr, "err");
        assert_eq!(out.exit_description(), "exit 3");
    }

    #[cfg(unix)]
    #[test]
    fn reports_signal_terminations() {
        let runner = runner(false, 1024);
        let out = runner.run(&Cmd::new("sh").args(["-c", "kill -TERM $$"]), deadline());
        assert_eq!(out.signal, Some(15));
        assert!(!out.success());
    }

    #[test]
    fn absolute_program_paths_are_spawned_directly() {
        let runner = runner(false, 1024);
        let out = runner.run(&Cmd::new("/bin/sh").args(["-c", "printf ok"]), deadline());
        assert!(out.success(), "{:?}", out.error);
        assert_eq!(out.stdout, "ok");
    }

    #[test]
    fn spawn_failures_become_command_errors() {
        let runner = runner(false, 1024);
        let out = runner.run(&Cmd::new("rs-security-checker-no-such-tool"), deadline());
        assert!(!out.success());
        assert!(
            out.error
                .as_deref()
                .unwrap_or_default()
                .contains("failed to spawn")
        );
    }

    #[test]
    fn per_command_timeout_terminates_the_process_group() {
        let runner = runner(false, 1024);
        let started = Instant::now();
        let out = runner.run(
            &Cmd::new("sh")
                .args(["-c", "sleep 5"])
                .timeout(Duration::from_millis(100)),
            deadline(),
        );
        assert!(out.timed_out);
        assert!(!out.success());
        assert_eq!(out.exit_description(), "timed out");
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn truncates_large_output_and_marks_it() {
        let runner = runner(false, 1024);
        let out = runner.run(
            &Cmd::new("sh").args(["-c", "yes x | head -c 10000"]),
            deadline(),
        );
        assert!(out.stdout.contains("[output truncated at 1024 bytes]"));
        assert!(out.stdout.len() < 2_000);
    }

    #[test]
    fn truncates_large_stderr_and_marks_it() {
        let runner = runner(false, 1024);
        let out = runner.run(
            &Cmd::new("sh").args(["-c", "yes x | head -c 10000 >&2"]),
            deadline(),
        );
        assert!(out.stderr.contains("[output truncated at 1024 bytes]"));
    }

    #[test]
    fn sudo_modes_are_explicit() {
        let never = Runner::new(SudoMode::Never, false, None, 1024, ui());
        assert!(!never.uses_sudo());

        let always = Runner::new(SudoMode::Always, false, None, 1024, ui());
        assert!(always.uses_sudo());

        let automatic = Runner::new(SudoMode::Auto, false, None, 1024, ui());
        assert_eq!(
            automatic.uses_sudo(),
            !automatic.is_root() && automatic.sudo_available()
        );
    }

    #[test]
    fn tool_lookup_uses_the_fixed_path() {
        let runner = runner(false, 1024);
        assert!(runner.tool_exists("sh"));
        assert!(!runner.tool_exists("rs-security-checker-no-such-tool"));
    }
}

#[cfg(unix)]
#[allow(clippy::items_after_test_module)]
extern "C" fn handle_interrupt(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
pub fn install_graceful_interrupt() {
    unsafe {
        libc::signal(libc::SIGINT, handle_interrupt as *const () as usize);
        libc::signal(libc::SIGTERM, handle_interrupt as *const () as usize);
    }
    thread::spawn(move || {
        while !INTERRUPTED.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(50));
        }
        if let Ok(groups) = CHILD_GROUPS.lock() {
            for pgid in groups.clone() {
                use nix::sys::signal::{Signal as ProcessSignal, killpg};
                use nix::unistd::Pid;
                let _ = killpg(Pid::from_raw(pgid as i32), ProcessSignal::SIGTERM);
            }
        }
        thread::sleep(Duration::from_millis(500));
        if let Ok(groups) = CHILD_GROUPS.lock() {
            for pgid in groups.clone() {
                use nix::sys::signal::{Signal as ProcessSignal, killpg};
                use nix::unistd::Pid;
                let _ = killpg(Pid::from_raw(pgid as i32), ProcessSignal::SIGKILL);
            }
        }
        std::process::exit(130);
    });
}

#[cfg(not(unix))]
pub fn install_graceful_interrupt() {}
