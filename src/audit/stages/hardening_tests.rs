#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::audit::test_support::{
        FakeRunner, expired_context, finding, finding_message, note, ok, stage_context, timed_out,
        write,
    };
    use crate::config::test_config;
    use crate::test_support::ui;

    fn paths(dir: &Path) -> HardeningPaths {
        HardeningPaths {
            sshd_config: dir.join("sshd_config"),
            sshd_config_dir: dir.join("sshd_config.d"),
            sysctl_conf: dir.join("sysctl.conf"),
            sysctl_dir: dir.join("sysctl.d"),
            passwd: dir.join("passwd"),
            shadow: dir.join("shadow"),
            sudoers: dir.join("sudoers"),
            sudoers_dir: dir.join("sudoers.d"),
            scan_roots: Vec::new(),
        }
    }

    fn run_with(
        dir: &Path,
        runner: &FakeRunner,
        configure: impl FnOnce(&mut HardeningPaths),
    ) -> StageReport {
        let cfg = test_config();
        let ui = ui();
        let ctx = stage_context(&cfg, runner, &ui);
        let mut paths = paths(dir);
        configure(&mut paths);
        run_with_paths(&ctx, &paths)
    }

    #[test]
    fn missing_configuration_is_reported_without_failing() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(finding(&report, Severity::Low, "SSH daemon"));
        assert!(finding(&report, Severity::Low, "sysctl"));
        assert!(finding(&report, Severity::Low, "firewall tooling"));
        assert!(note(&report, "/etc/shadow"));
    }

    #[test]
    fn insecure_ssh_settings_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sshd_config"),
            "PermitRootLogin yes\nPasswordAuthentication yes\n\
             PermitEmptyPasswords yes\nPermitUserEnvironment yes\nUsePAM no\n\
             X11Forwarding yes\nMaxAuthTries 10\nLoginGraceTime 120\nClientAliveInterval 0\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});

        assert!(finding(&report, Severity::High, "root login"));
        assert!(finding(&report, Severity::Medium, "password authentication"));
        assert!(finding(&report, Severity::High, "empty passwords"));
        assert!(finding(&report, Severity::Medium, "environment files"));
        assert!(finding(&report, Severity::Medium, "PAM disabled"));
        assert!(finding(&report, Severity::Low, "X11"));
        assert!(finding(&report, Severity::Low, "authentication attempts"));
        assert!(finding(&report, Severity::Low, "LoginGraceTime"));
        assert!(finding(&report, Severity::Low, "never expire"));
    }

    #[test]
    fn ssh_root_login_modes_are_classified() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sshd_config"),
            "PermitRootLogin prohibit-password\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(finding(&report, Severity::Info, "key-based"));

        write(
            &dir.path().join("sshd_config"),
            "PermitRootLogin forced-commands-only\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(finding(&report, Severity::Low, "forced commands"));
    }

    #[test]
    fn empty_sshd_output_falls_back_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("sshd_config"), "PermitRootLogin yes\n");
        let runner = FakeRunner::new(&["sshd"]).respond("sshd -T", ok(""));
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(report.output.contains("file fallback"));
        assert!(finding(&report, Severity::High, "root login"));
    }

    #[test]
    fn sshd_dash_t_output_is_preferred() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("sshd_config"), "PermitRootLogin no\n");
        let runner = FakeRunner::new(&["sshd"]).respond(
            "sshd -T",
            ok("permitrootlogin yes\npasswordauthentication yes\n"),
        );
        let report = run_with(dir.path(), &runner, |_| {});

        assert!(report.output.contains("sshd -T"));
        assert!(finding(&report, Severity::High, "root login"));
        assert_eq!(runner.calls(), vec!["sshd -T"]);
    }

    #[test]
    fn ssh_dropins_override_the_main_file() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("sshd_config"), "PermitRootLogin yes\n");
        write(
            &dir.path().join("sshd_config.d/50-cloud.conf"),
            "PermitRootLogin no\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(!finding_message(&report, "root login"));
    }

    #[test]
    fn ssh_parser_ignores_comments_and_match_blocks() {
        let settings = parse_ssh_settings(
            "# comment\nPasswordAuthentication no\nMatch User demo\nPasswordAuthentication yes\n",
            true,
        );
        assert_eq!(
            settings.get("passwordauthentication").map(String::as_str),
            Some("no")
        );

        let effective = parse_ssh_settings("permitrootlogin \"no\"\n", false);
        assert_eq!(
            effective.get("permitrootlogin").map(String::as_str),
            Some("no")
        );
    }

    #[test]
    fn secure_ssh_settings_pass() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sshd_config"),
            "PermitRootLogin no\nPasswordAuthentication no\nUsePAM yes\nX11Forwarding no\n",
        );
        let runner = FakeRunner::new(&["ufw"]).respond("ufw status", ok("Status: active\n"));
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(!finding_message(&report, "SSH"));
    }

    #[test]
    fn unsafe_sysctl_values_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sysctl.conf"),
            "# kernel hardening\nkernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 0\nnot a setting\n",
        );
        write(
            &dir.path().join("sysctl.d/99-hardening.conf"),
            "net.ipv4.conf.all.accept_redirects = 1\nfs.protected_symlinks = 1\n",
        );
        write(&dir.path().join("sysctl.d/README.txt"), "ignored\n");
        fs::create_dir_all(dir.path().join("sysctl.d/nested.conf")).unwrap();
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});

        assert!(finding(&report, Severity::Medium, "randomize_va_space"));
        assert!(finding(&report, Severity::Medium, "tcp_syncookies"));
        assert!(finding(&report, Severity::Medium, "accept_redirects"));
        assert!(report.output.contains("4/15 security-relevant sysctl keys"));
    }

    #[test]
    fn sysctl_dropins_override_main_values() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("sysctl.conf"), "net.ipv4.ip_forward = 1\n");
        write(
            &dir.path().join("sysctl.d/10-forward.conf"),
            "net.ipv4.ip_forward = 0\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(!finding_message(&report, "ip_forward"));
    }

    #[test]
    fn live_sysctl_values_override_files() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sysctl.conf"),
            "kernel.randomize_va_space = 2\n",
        );
        let runner = FakeRunner::new(&["sysctl"])
            .respond("sysctl -a", ok("kernel.randomize_va_space = 0\n"));
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(finding(&report, Severity::Medium, "randomize_va_space = 0"));
    }

    #[test]
    fn ufw_active_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(&["ufw"])
            .respond("ufw status", ok("Status: active\n22/tcp ALLOW Anywhere\n"));
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(note(&report, "ufw"));
        assert!(!report.output.contains("no active firewall"));
    }

    #[test]
    fn inactive_tools_are_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(&["ufw", "nft", "iptables"])
            .respond("ufw status", ok("Status: inactive\n"))
            .respond("nft list ruleset", ok(""))
            .respond("iptables -S", ok("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n"));
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(finding(&report, Severity::Medium, "no active firewall"));
    }

    #[test]
    fn nft_rules_are_detected_when_ufw_is_inactive() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(&["ufw", "nft"])
            .respond("ufw status", ok("Status: inactive\n"))
            .respond("nft list ruleset", ok("table inet filter {\n}\n"));
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(note(&report, "nftables"));
    }

    #[test]
    fn iptables_rules_are_detected_as_a_last_resort() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(&["iptables"]).respond(
            "iptables -S",
            ok("-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"),
        );
        let report = run_with(dir.path(), &runner, |_| {});
        assert!(note(&report, "iptables"));
    }

    #[test]
    fn firewall_timeout_marks_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new(&["ufw"]).respond("ufw status", timed_out());
        let report = run_with(dir.path(), &runner, |_| {});
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding_message(&report, "ufw status timed out"));
    }

    #[test]
    fn nft_and_iptables_timeouts_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let nft = FakeRunner::new(&["nft"]).respond("nft list ruleset", timed_out());
        let report = run_with(dir.path(), &nft, |_| {});
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding_message(&report, "nft list ruleset timed out"));

        let iptables = FakeRunner::new(&["iptables"]).respond("iptables -S", timed_out());
        let report = run_with(dir.path(), &iptables, |_| {});
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding_message(&report, "iptables -S timed out"));
    }

    #[test]
    fn no_firewall_tools_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(finding(&report, Severity::Low, "no firewall tooling"));
    }

    #[test]
    fn nopasswd_and_noauth_sudo_rules_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sudoers"),
            "Defaults !authenticate\n%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n",
        );
        write(
            &dir.path().join("sudoers.d/90-demo"),
            "deploy ALL=(ALL) NOPASSWD: /bin/systemctl restart app\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});

        assert!(finding(&report, Severity::Medium, "NOPASSWD"));
        assert!(finding(&report, Severity::High, "!authenticate"));
    }

    #[test]
    fn clean_sudoers_pass() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("sudoers"), "root ALL=(ALL:ALL) ALL\n");
        write(
            &dir.path().join("sudoers.d/90-demo"),
            "deploy ALL=(ALL) /bin/systemctl status app\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(report.output.contains("no NOPASSWD"));
    }

    #[test]
    fn scan_detects_dangerous_file_modes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();

        let suid = root.join("custom-tool");
        write(&suid, "#!/bin/sh\n");
        fs::set_permissions(&suid, fs::Permissions::from_mode(0o4755)).unwrap();

        let known = root.join("sudo");
        write(&known, "#!/bin/sh\n");
        fs::set_permissions(&known, fs::Permissions::from_mode(0o4755)).unwrap();

        let world = root.join("world.txt");
        write(&world, "data");
        fs::set_permissions(&world, fs::Permissions::from_mode(0o666)).unwrap();

        let open_dir = root.join("open");
        fs::create_dir_all(&open_dir).unwrap();
        fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).unwrap();

        let sticky = root.join("sticky");
        fs::create_dir_all(&sticky).unwrap();
        fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).unwrap();

        let report = run_with(dir.path(), &FakeRunner::new(&[]), |paths| {
            paths.scan_roots = vec![root.clone()];
        });

        assert!(finding(&report, Severity::Low, "unexpected SUID/SGID"));
        assert!(finding(&report, Severity::Medium, "world-writable file"));
        assert!(finding(&report, Severity::Medium, "world-writable directories"));
        assert!(!report.output.contains("sticky"));
    }

    #[test]
    fn suid_in_shared_locations_is_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("home");
        fs::create_dir_all(&shared).unwrap();
        let suid = shared.join("backdoor");
        write(&suid, "#!/bin/sh\n");
        fs::set_permissions(&suid, fs::Permissions::from_mode(0o4755)).unwrap();

        let report = run_with(dir.path(), &FakeRunner::new(&[]), |paths| {
            paths.scan_roots = vec![shared];
        });
        assert!(finding(&report, Severity::High, "shared location"));
    }

    #[test]
    fn scan_handles_unreadable_and_symlinked_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let target = dir.path().join("target");
        write(&target, "data");
        std::os::unix::fs::symlink(&target, root.join("link")).unwrap();

        let scan = scan_filesystem(&[root, dir.path().join("missing")]);
        assert_eq!(scan.entries, 1);
        assert!(scan.suid.is_empty());
    }

    #[test]
    fn scan_counts_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..20 {
            write(&dir.path().join(format!("file-{index}")), "x");
        }
        let scan = scan_filesystem(&[dir.path().to_path_buf()]);
        assert!(!scan.truncated);
        assert_eq!(scan.entries, 21);
    }

    #[test]
    fn long_path_lists_are_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();
        for index in 0..21 {
            let path = root.join(format!("open-{index}"));
            write(&path, "x");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        }
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |paths| {
            paths.scan_roots = vec![root];
        });
        assert!(report.output.contains("... and 1 more"));
    }

    #[test]
    fn expired_deadline_marks_the_stage_timed_out() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config();
        let runner = FakeRunner::new(&[]);
        let ui = ui();
        let ctx = expired_context(&cfg, &runner, &ui);
        let report = run_with_paths(&ctx, &paths(dir.path()));
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(finding_message(&report, "global deadline"));
    }

    #[test]
    fn account_problems_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             toor::0:0:toor:/root:/bin/sh\n\
             alice:x:1000:1000::/home/alice:/bin/bash\n",
        );
        write(
            &dir.path().join("shadow"),
            "root:$6$salt$hash:19000:0:99999:7:::\n\
             empty::19000:0:99999:7:::\n\
             weak:$1$salt$hash:19000:0:99999:7:::\n\
             locked:!$6$salt$hash:19000:0:99999:7:::\n\
             malformed\n# comment\n",
        );
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});

        assert!(finding(&report, Severity::High, "UID 0"));
        assert!(finding(&report, Severity::High, "empty password field"));
        assert!(finding(&report, Severity::High, "empty shadow password"));
        assert!(finding(&report, Severity::Low, "MD5"));
        assert!(report.output.contains("1 locked account"));
    }

    #[test]
    fn unreadable_shadow_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let shadow_dir = dir.path().join("shadow");
        fs::create_dir_all(&shadow_dir).unwrap();
        let report = run_with(dir.path(), &FakeRunner::new(&[]), |_| {});
        assert!(note(&report, "could not read /etc/shadow"));
    }

    #[test]
    fn clean_hardening_passes() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sshd_config"),
            "PermitRootLogin no\nPasswordAuthentication no\nUsePAM yes\n\
             X11Forwarding no\nMaxAuthTries 4\nLoginGraceTime 30\nClientAliveInterval 300\n",
        );
        write(
            &dir.path().join("sysctl.conf"),
            "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\n",
        );
        write(
            &dir.path().join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        );
        write(
            &dir.path().join("shadow"),
            "root:$6$salt$hash:19000:0:99999:7:::\nalice:$y$salt$hash:19000:0:99999:7:::\n",
        );
        write(&dir.path().join("sudoers"), "root ALL=(ALL:ALL) ALL\n");

        let runner = FakeRunner::new(&["ufw"]).respond("ufw status", ok("Status: active\n"));
        let report = run_with(dir.path(), &runner, |_| {});
        assert_eq!(report.status, StageStatus::Passed);
        assert_eq!(report.highest_severity(), Severity::Info);
    }

    #[test]
    fn dry_run_skips_command_and_filesystem_checks() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config();
        cfg.dry_run = true;
        let runner = FakeRunner::new(&["ufw", "sshd", "sysctl"]);
        let ui = ui();
        let ctx = stage_context(&cfg, &runner, &ui);
        let report = run_with_paths(&ctx, &paths(dir.path()));

        assert!(note(&report, "dry-run"));
        assert!(runner.calls().is_empty());
        assert!(!report.output.contains("permission denied"));
    }
}
