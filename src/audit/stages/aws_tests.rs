#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::audit::test_support::{
        FakeRunner, exit, expired_context, finding, finding_message, note, ok, stage_context,
        timed_out, write,
    };
    use crate::config::test_config;
    use crate::test_support::ui;

    const V1_URL: &str = crate::constants::AWS_INSTANCE_ID_URL;
    const TOKEN_URL: &str = crate::constants::AWS_TOKEN_URL;
    const DOC_URL: &str = crate::constants::AWS_INSTANCE_IDENTITY_DOCUMENT_URL;
    const ROLE_URL: &str = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
    const SSM: &str =
        "systemctl show amazon-ssm-agent.service --property=LoadState,ActiveState --no-pager";
    const CLOUDWATCH: &str = "systemctl show amazon-cloudwatch-agent.service --property=LoadState,ActiveState --no-pager";
    const ECS: &str = "systemctl show ecs.service --property=LoadState,ActiveState --no-pager";
    const NTP: &str = "timedatectl show --property=NTPSynchronized --value";

    fn paths(dir: &Path) -> AwsPaths {
        AwsPaths {
            os_release: dir.join("os-release"),
            user_data: vec![dir.join("user-data.txt")],
            home_roots: vec![dir.join("home")],
            env_files: vec![dir.join("environment")],
            profile_dir: dir.join("profile.d"),
            ecs_config: dir.join("ecs.config"),
            metadata_root: METADATA_ROOT.to_owned(),
        }
    }

    fn run_with(
        dir: &Path,
        runner: &FakeRunner,
        configure: impl FnOnce(&mut AwsPaths),
    ) -> StageReport {
        let cfg = test_config();
        let ui = ui();
        let ctx = stage_context(&cfg, runner, &ui);
        let mut paths = paths(dir);
        configure(&mut paths);
        run_with_paths(&ctx, &paths)
    }

    fn curl_key(extra: &[&str], url: &str) -> String {
        let mut key = format!("curl {}", CURL_ARGS.join(" "));
        for argument in extra {
            key.push(' ');
            key.push_str(argument);
        }
        key.push(' ');
        key.push_str(url);
        key
    }

    fn token_key() -> String {
        curl_key(
            &[
                "-X",
                "PUT",
                "-H",
                "X-aws-ec2-metadata-token-ttl-seconds: 60",
            ],
            TOKEN_URL,
        )
    }

    fn token_get_key(url: &str, token: &str) -> String {
        curl_key(&["-H", &format!("X-aws-ec2-metadata-token: {token}")], url)
    }

    fn ubuntu_release() -> &'static str {
        "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"
    }

    fn all_units_missing(runner: FakeRunner) -> FakeRunner {
        runner
            .respond(SSM, ok("LoadState=not-found\nActiveState=inactive\n"))
            .respond(
                CLOUDWATCH,
                ok("LoadState=not-found\nActiveState=inactive\n"),
            )
            .respond(ECS, ok("LoadState=not-found\nActiveState=inactive\n"))
    }

    #[test]
    fn clean_aws_host_passes() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        write(&dir.path().join("user-data.txt"), "#cloud-config\n");
        write(&dir.path().join("environment"), "");
        let runner = all_units_missing(
            FakeRunner::new(&["curl", "systemctl", "timedatectl"])
                .respond(&curl_key(&[], V1_URL), exit(22, "401"))
                .respond(&token_key(), exit(7, "blocked"))
                .respond(NTP, ok("yes\n")),
        );
        let report = run_with(dir.path(), &runner, |_| {});

        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.findings.is_empty());
        assert!(report.output.contains("Ubuntu 24.04 LTS"));
        assert!(note(&report, "not reachable"));
    }

    #[test]
    fn detects_imdsv1_and_reports_instance_details() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = all_units_missing(
            FakeRunner::new(&["curl", "systemctl", "timedatectl"])
                .respond(&curl_key(&[], V1_URL), ok("i-0123456789abcdef0\n"))
                .respond(&token_key(), ok("token-123\n"))
                .respond(
                    &token_get_key(DOC_URL, "token-123"),
                    ok("{\"instanceId\":\"i-0123456789abcdef0\",\"region\":\"eu-west-1\",\"availabilityZone\":\"eu-west-1a\",\"instanceType\":\"t3.micro\",\"imageId\":\"ami-123\"}\n"),
                )
                .respond(&token_get_key(ROLE_URL, "token-123"), ok("app-role\n"))
                .respond(NTP, ok("yes\n")),
        );
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(finding(&report, Severity::High, "IMDSv1"));
        assert!(report.output.contains("region: eu-west-1"));
        assert!(report.output.contains("instance-id: i-0123456789abcdef0"));
        assert!(report.output.contains("instance profile role: app-role"));
        assert!(!report.output.contains("token-123"));
    }

    #[test]
    fn imdsv2_enforced_passes_metadata_checks() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = all_units_missing(
            FakeRunner::new(&["curl", "systemctl", "timedatectl"])
                .respond(&curl_key(&[], V1_URL), exit(22, "401"))
                .respond(&token_key(), ok("token-123"))
                .respond(
                    &token_get_key(DOC_URL, "token-123"),
                    ok("{\"region\":\"eu-west-1\"}\n"),
                )
                .respond(&token_get_key(ROLE_URL, "token-123"), ok(""))
                .respond(NTP, ok("yes\n")),
        );
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(!finding_message(&report, "IMDSv1"));
        assert!(note(&report, "IMDSv2"));
    }

    #[test]
    fn metadata_timeout_marks_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = FakeRunner::new(&["curl", "systemctl", "timedatectl"])
            .respond(&curl_key(&[], V1_URL), timed_out())
            .respond(&token_key(), timed_out());
        let report = run_with(dir.path(), &runner, |_| {});
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding(&report, Severity::Medium, "IMDSv1 probe timed out"));
    }

    #[test]
    fn static_credentials_and_loose_permissions_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let home_credentials = dir.path().join("home/alice/.aws/credentials");
        write(
            &home_credentials,
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret\n",
        );
        fs::set_permissions(&home_credentials, fs::Permissions::from_mode(0o644)).unwrap();
        let root_credentials = dir.path().join("root/.aws/config");
        write(
            &root_credentials,
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        );
        fs::set_permissions(&root_credentials, fs::Permissions::from_mode(0o600)).unwrap();

        let report = run_with(dir.path(), &FakeRunner::new(&[]), |paths| {
            paths.home_roots = vec![dir.path().join("home"), dir.path().join("root")];
        });

        assert!(finding(&report, Severity::High, "credential material is stored"));
        assert!(finding(&report, Severity::Medium, "readable by group/others"));
        assert!(!report.output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!report.output.contains("secret"));
    }

    #[test]
    fn secrets_in_user_data_environment_and_ecs_config_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        write(
            &dir.path().join("user-data.txt"),
            "#cloud-config\nruncmd:\n  - export AWS_SECRET_ACCESS_KEY=abc\n-----BEGIN OPENSSH PRIVATE KEY-----\n",
        );
        write(
            &dir.path().join("environment"),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        );
        write(
            &dir.path().join("profile.d/aws.sh"),
            "export AWS_SECRET_ACCESS_KEY=xyz\n",
        );
        write(
            &dir.path().join("ecs.config"),
            "ECS_CLUSTER=prod\nAWS_SECRET_ACCESS_KEY=abc\n",
        );

        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});

        assert!(finding(&report, Severity::High, "user-data"));
        assert!(finding(&report, Severity::High, "private key material"));
        assert!(finding(&report, Severity::High, "exported by"));
        assert!(finding(&report, Severity::High, "ECS agent config"));
        assert!(!report.output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn inactive_agents_and_unsynced_clock_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        write(&dir.path().join("ecs.config"), "ECS_CLUSTER=prod\n");
        let runner = FakeRunner::new(&["curl", "systemctl", "timedatectl"])
            .respond(&curl_key(&[], V1_URL), exit(22, "401"))
            .respond(&token_key(), exit(7, "blocked"))
            .respond(SSM, ok("LoadState=loaded\nActiveState=inactive\n"))
            .respond(CLOUDWATCH, ok("LoadState=loaded\nActiveState=inactive\n"))
            .respond(ECS, ok("LoadState=loaded\nActiveState=inactive\n"))
            .respond(NTP, ok("no\n"));
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(finding(&report, Severity::Low, "SSM agent"));
        assert!(finding(&report, Severity::Info, "CloudWatch"));
        assert!(finding(&report, Severity::Medium, "ECS agent"));
        assert!(finding(&report, Severity::Low, "NTP-synchronized"));
    }

    #[test]
    fn unsupported_os_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("os-release"),
            "ID=amzn\nVERSION_ID=\"2023\"\nPRETTY_NAME=\"Amazon Linux 2023\"\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(finding(&report, Severity::Low, "not Debian/Ubuntu"));
    }

    #[test]
    fn missing_os_release_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(finding(&report, Severity::Low, "could not read"));
    }

    #[test]
    fn dry_run_skips_remote_and_service_checks() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let mut cfg = test_config();
        cfg.dry_run = true;
        let runner = FakeRunner::new(&["curl", "systemctl", "timedatectl"]);
        let ui = ui();
        let ctx = stage_context(&cfg, &runner, &ui);
        let report = run_with_paths(&ctx, &paths(dir.path()));

        assert!(runner.calls().is_empty());
        assert!(note(&report, "dry-run"));
    }

    #[test]
    fn parse_os_release_handles_quotes_and_comments() {
        let values = parse_os_release(
            "# comment\nID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nmalformed\n",
        );
        assert_eq!(values.get("id").map(String::as_str), Some("ubuntu"));
        assert_eq!(values.get("version_id").map(String::as_str), Some("22.04"));
        assert_eq!(
            values.get("pretty_name").map(String::as_str),
            Some("Ubuntu 22.04.4 LTS")
        );
    }

    #[test]
    fn credential_discovery_covers_home_roots_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(home.join("alice")).unwrap();
        fs::create_dir_all(home.join("bob")).unwrap();
        let mut paths = paths(dir.path());
        paths.home_roots = vec![home, dir.path().join("root")];

        let files = credential_files(&paths);
        assert!(files.contains(&dir.path().join("home/alice/.aws/credentials")));
        assert!(files.contains(&dir.path().join("home/bob/.aws/config")));
        assert!(files.contains(&dir.path().join("root/.aws/credentials")));
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        let text = format!("{}é", "a".repeat(5));
        let truncated = truncate(&text, 6);
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn missing_version_and_empty_optional_files_are_handled() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("os-release"),
            "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux\"\n",
        );
        write(&dir.path().join("user-data.txt"), "");
        write(&dir.path().join("environment"), "");
        write(&dir.path().join("ecs.config"), "");

        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});

        assert!(report.output.contains("VERSION_ID: unknown"));
        assert!(
            report
                .output
                .contains("No AWS-related files were found to scan.")
        );
    }

    #[test]
    fn reachable_imdsv1_without_a_token_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = FakeRunner::new(&["curl"])
            .respond(&curl_key(&[], V1_URL), ok("i-0123456789abcdef0\n"))
            .respond(&token_key(), exit(7, "blocked"));
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(report.output.contains("IMDSv1: reachable"));
        assert!(report.output.contains("IMDSv2: token endpoint unavailable"));
        assert!(finding(&report, Severity::Low, "IMDSv2 token could not be obtained"));
    }

    #[test]
    fn metadata_request_timeouts_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = FakeRunner::new(&["curl"])
            .respond(&curl_key(&[], V1_URL), exit(22, "401"))
            .respond(&token_key(), ok("token-123"))
            .respond(&token_get_key(DOC_URL, "token-123"), timed_out())
            .respond(&token_get_key(ROLE_URL, "token-123"), timed_out());
        let report = run_with(dir.path(), &runner, |_| {});

        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding(&report, Severity::Medium, "identity document request timed out"));
        assert!(finding(&report, Severity::Medium, "IAM role enumeration timed out"));
    }

    #[test]
    fn invalid_identity_document_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = FakeRunner::new(&["curl"])
            .respond(&curl_key(&[], V1_URL), exit(22, "401"))
            .respond(&token_key(), ok("token-123"))
            .respond(&token_get_key(DOC_URL, "token-123"), ok("not-json"))
            .respond(&token_get_key(ROLE_URL, "token-123"), ok(""));
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(note(&report, "not valid JSON"));
    }

    #[test]
    fn unreadable_credential_locations_are_noted() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        fs::create_dir_all(dir.path().join("home/alice/.aws/credentials")).unwrap();
        fs::create_dir_all(dir.path().join("user-data.txt")).unwrap();
        fs::create_dir_all(dir.path().join("environment")).unwrap();
        fs::create_dir_all(dir.path().join("ecs.config")).unwrap();

        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        let read_errors = report
            .notes
            .iter()
            .filter(|note| note.contains("could not read"))
            .count();
        assert_eq!(read_errors, 4, "notes: {:?}", report.notes);
    }

    #[test]
    fn agent_failures_and_clock_timeout_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        write(&dir.path().join("ecs.config"), "ECS_CLUSTER=prod\n");
        let runner = FakeRunner::new(&["curl", "systemctl", "timedatectl"])
            .respond(&curl_key(&[], V1_URL), exit(22, "401"))
            .respond(&token_key(), exit(7, "blocked"))
            .respond(SSM, timed_out())
            .respond(CLOUDWATCH, exit(1, "unit unavailable"))
            .respond(
                ECS,
                ok("garbage\nLoadState=not-found\nActiveState=inactive\n"),
            )
            .respond(NTP, timed_out());
        let report = run_with(dir.path(), &runner, |_| {});

        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding(&report, Severity::Medium, "systemctl show amazon-ssm-agent.service timed out"));
        assert!(finding(&report, Severity::Medium, "ECS agent unit is not installed"));
        assert!(finding(&report, Severity::Medium, "NTP synchronization check timed out"));
    }

    #[test]
    fn clock_check_failure_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let runner = FakeRunner::new(&["curl", "timedatectl"])
            .respond(&curl_key(&[], V1_URL), exit(22, "401"))
            .respond(&token_key(), exit(7, "blocked"))
            .respond(NTP, exit(1, "not supported"));
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(note(&report, "could not report clock synchronization state"));
    }

    #[test]
    fn unit_reporting_covers_active_inactive_and_unknown_states() {
        let mut report = StageReport::new(StageId::Aws);
        let ecs_config = Path::new("/nonexistent/ecs.config");
        report_unit(
            "custom.service",
            UnitStatus::Active,
            ecs_config,
            &mut report,
        );
        report_unit(
            "custom.service",
            UnitStatus::Inactive,
            ecs_config,
            &mut report,
        );
        report_unit(
            "custom.service",
            UnitStatus::Unknown,
            ecs_config,
            &mut report,
        );

        assert!(report.output.contains("custom.service: active"));
        assert!(report.output.contains("custom.service: inactive"));
        assert!(report.output.contains("custom.service: unknown"));
        assert!(note(&report, "custom.service is active"));
    }

    #[test]
    fn credential_discovery_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        for index in 0..40 {
            fs::create_dir_all(home.join(format!("user{index}"))).unwrap();
        }
        let mut paths = paths(dir.path());
        paths.home_roots = vec![home, dir.path().join("root")];

        let files = credential_files(&paths);
        assert_eq!(files.len(), MAX_CREDENTIAL_FILES);
    }

    #[test]
    fn expired_deadline_marks_the_stage_as_timed_out() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("os-release"), ubuntu_release());
        let mut cfg = test_config();
        cfg.dry_run = true;
        let runner = FakeRunner::new(&[]);
        let ui = ui();
        let ctx = expired_context(&cfg, &runner, &ui);
        let report = run_with_paths(&ctx, &paths(dir.path()));

        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding_message(&report, "reached the global deadline"));
    }
}
