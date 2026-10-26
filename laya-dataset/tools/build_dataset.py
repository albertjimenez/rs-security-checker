#!/usr/bin/env python3
"""Build the Laya System One security-triage dataset.

Every JSONL row is a typed-decision case:

    {"state": ..., "questions": {...}, "expected": {...}}

``state`` is the compact audit JSON that ``build_context()`` in ``src/laya/mod.rs`` passes to the
in-process Laya model. ``questions`` are the two runtime questions (``notify`` and ``severity``)
and ``expected`` holds their choice labels. There is no generated prose: the model scores the
options and the checker reads the winning label.

Edit the stage profiles or add cross-stage scenarios below, then run:

    python tools/build_dataset.py
    python tools/validate_dataset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
STARTED_AT = "2026-01-01T00:00:00Z"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}
STATUSES = {"passed", "warnings", "failed", "skipped", "timed_out"}

STAGES = [
    ("precheck", "Precheck & Dependencies"),
    ("docker", "Docker Security Audit"),
    ("clamav", "ClamAV Scan"),
    ("debsums", "Debsums Integrity"),
    ("rootkit", "Rootkit Audits"),
    ("persistence", "Persistence & Account Audit"),
    ("network", "Network Sockets & Pending Patches"),
    ("web", "Web Server Logs"),
    ("auth", "Authentication Logs"),
    ("hardening", "Host Hardening"),
    ("aws", "AWS Host & Metadata"),
]
STAGE_TITLES = dict(STAGES)

# Keep these byte-for-byte in sync with `laya_questions()` in src/laya/mod.rs. The checked-in
# `data/questions.json` is compared against the Rust source by a Rust test, and
# `validate_dataset.py` compares every row against the same file.
QUESTIONS = {
    "notify": {
        "type": "choice",
        "instructions": "Does this audit warrant notifying the on-call engineer?",
        "criteria": ["true", "false"],
    },
    "severity": {
        "type": "choice",
        "instructions": "What is the highest triage severity warranted by this audit?",
        "criteria": SEVERITIES,
    },
}


@dataclass(frozen=True)
class Finding:
    stage: str
    severity: str
    message: str


@dataclass
class Scenario:
    id: str
    split: str
    notify: bool
    severity: str
    findings: list[Finding] = field(default_factory=list)
    statuses: dict[str, str] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=dict)
    host: str = "audit-host"
    truncate_at: int | None = None


# Each profile supplies the short, tool-specific detail used by the variants below.
STAGE_PROFILES = {
    "precheck": {
        "tool": "dpkg/apt precheck",
        "low": "one optional audit package is missing",
        "medium_expected": "a recommended package is absent on a minimal image",
        "medium_action": "a required audit tool is missing, reducing coverage",
        "high": "the package database is locked and dependency state cannot be verified",
        "critical": "dpkg reports a corrupted package database",
        "failure": "dpkg dependency inspection",
    },
    "docker": {
        "tool": "Docker audit",
        "low": "a stopped container has no restart policy",
        "medium_expected": "a development container runs without a memory limit",
        "medium_action": "a container runs as root with no-new-privileges disabled",
        "high": "a container mounts the Docker socket",
        "critical": "a container runs privileged with host PID access",
        "failure": "docker inspect",
    },
    "clamav": {
        "tool": "ClamAV",
        "low": "the signature database is older than 24 hours",
        "medium_expected": "freshclam is not configured for automatic updates on an ephemeral host",
        "medium_action": "the signature database is older than 7 days",
        "high": "clamscan found a malicious file in /tmp",
        "critical": "clamscan found malware in a running container volume",
        "failure": "clamscan",
    },
    "debsums": {
        "tool": "debsums",
        "low": "one conffile differs from the package default",
        "medium_expected": "a locally customized conffile differs from the package default",
        "medium_action": "several package files were modified outside dpkg",
        "high": "a core system binary fails the package checksum",
        "critical": "multiple coreutils binaries fail the package checksum",
        "failure": "debsums -cs",
    },
    "rootkit": {
        "tool": "rootkit audit",
        "low": "chkrootkit reported a known benign warning",
        "medium_expected": "rkhunter reported a known false positive for a hidden file in /dev/shm",
        "medium_action": "rkhunter warnings require manual review",
        "high": "chkrootkit reported a suspicious hidden process",
        "critical": "rkhunter reported a rootkit signature match",
        "failure": "chkrootkit/rkhunter",
    },
    "persistence": {
        "tool": "persistence audit",
        "low": "an authorized_keys file lists a deploy key",
        "medium_expected": "an enabled vendor systemd unit matches the local/custom/run/tmp pattern",
        "medium_action": "an enabled systemd unit runs from /tmp",
        "high": "a non-root account has UID 0",
        "critical": "multiple non-root accounts have UID 0",
        "failure": "crontab and authorized_keys inspection",
    },
    "network": {
        "tool": "network audit",
        "low": "an established outbound connection to the package mirror",
        "medium_expected": "a wildcard listener is bound to a private interface",
        "medium_action": "a database service listens on 0.0.0.0",
        "high": "pending Debian/Ubuntu security updates include OpenSSL",
        "critical": "a critical kernel security update has been pending for weeks",
        "failure": "ss/apt-get network inspection",
    },
    "web": {
        "tool": "web log audit",
        "low": "a scanner user-agent probed the site",
        "medium_expected": "a handful of 404 responses came from a monitoring probe",
        "medium_action": "repeated login failures came from a single IP address",
        "high": "SQL injection attempts target the login endpoint",
        "critical": "Log4Shell exploit attempts were observed",
        "failure": "web log parsing",
    },
    "auth": {
        "tool": "authentication log audit",
        "low": "a single failed SSH login",
        "medium_expected": "a failed login came from an internal monitoring host",
        "medium_action": "sudo denials were recorded for an unexpected user",
        "high": "a successful SSH login followed a burst of failures",
        "critical": "a break-in marker indicates an active compromise",
        "failure": "auth log parsing",
    },
    "hardening": {
        "tool": "host hardening audit",
        "low": "a world-writable path was found under /srv",
        "medium_expected": "a vendor sysctl override differs from the hardening baseline",
        "medium_action": "SSH password authentication is enabled",
        "high": "the host firewall is inactive",
        "critical": "the root account has an empty password",
        "failure": "sshd/sysctl/firewall inspection",
    },
    "aws": {
        "tool": "AWS host audit",
        "low": "the IMDSv2 token endpoint could not be verified",
        "medium_expected": "the ECS agent is installed but not running on a host that is not registered to a cluster",
        "medium_action": "the ECS agent config exists but the agent unit is not installed",
        "high": "EC2 IMDSv1 is enabled",
        "critical": "long-term AWS credentials are stored in world-readable user-data",
        "failure": "EC2 metadata and AWS agent inspection",
    },
}


def _finding(stage: str, severity: str, message: str) -> Finding:
    return Finding(stage=stage, severity=severity, message=message)


# Only these stages emit `critical` findings at runtime. For every other stage the most severe
# variant is `high`; keeping the label aligned with the finding severity avoids teaching laya to
# over-escalate.
CRITICAL_STAGES = {"clamav", "persistence"}


def _stage_variants(stage: str, profile: dict[str, str]) -> list[Scenario]:
    """Return the reusable scenario shapes for one stage."""
    tool = profile["tool"]
    high_severity = "critical" if stage in CRITICAL_STAGES else "high"
    critical_severity = "critical" if stage in CRITICAL_STAGES else "high"
    high_label = "Critical" if high_severity == "critical" else "High-severity"
    critical_label = "Critical" if critical_severity == "critical" else "High-severity"
    return [
        Scenario(
            id=f"{stage}-clean",
            split="train",
            notify=False,
            severity="info",
        ),
        Scenario(
            id=f"{stage}-low-noise",
            split="train",
            notify=False,
            severity="low",
            findings=[_finding(stage, "low", f"{tool}: {profile['low']}.")],
        ),
        Scenario(
            id=f"{stage}-medium-expected",
            split="train",
            notify=False,
            severity="medium",
            findings=[_finding(stage, "medium", f"{tool}: {profile['medium_expected']}.")],
        ),
        Scenario(
            id=f"{stage}-medium-action",
            split="train",
            notify=True,
            severity="medium",
            findings=[_finding(stage, "medium", f"{tool}: {profile['medium_action']}.")],
        ),
        Scenario(
            id=f"{stage}-high",
            split="train",
            notify=True,
            severity=high_severity,
            findings=[_finding(stage, high_severity, f"{tool}: {profile['high']}.")],
        ),
        Scenario(
            id=f"{stage}-critical",
            split="train",
            notify=True,
            severity=critical_severity,
            findings=[_finding(stage, critical_severity, f"{tool}: {profile['critical']}.")],
        ),
        Scenario(
            id=f"{stage}-coverage-failed",
            split="train",
            notify=True,
            severity="high",
            findings=[_finding(stage, "high", f"{tool}: {profile['failure']}.")],
            statuses={stage: "failed"},
            notes={
                stage: [
                    "the stage did not complete; see the artifact for the captured error",
                ]
            },
        ),
        Scenario(
            id=f"{stage}-coverage-timeout",
            split="train",
            notify=True,
            severity="high",
            findings=[_finding(stage, "high", f"{tool}: {profile['failure']}.")],
            statuses={stage: "timed_out"},
            notes={
                stage: [
                    "the stage exceeded its deadline; the artifact is incomplete",
                ]
            },
        ),
    ]


def _stage_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for stage_index, (stage, _title) in enumerate(STAGES):
        variants = _stage_variants(stage, STAGE_PROFILES[stage])
        valid_index = stage_index % len(variants)
        test_index = (stage_index + 3) % len(variants)
        for variant_index, variant in enumerate(variants):
            if variant_index == valid_index:
                variant.split = "valid"
            elif variant_index == test_index:
                variant.split = "test"
            else:
                variant.split = "train"
            scenarios.append(variant)
    return scenarios


def _cross_stage_scenarios() -> list[Scenario]:
    return [
        Scenario(
            id="cross-malware-rootkit",
            split="train",
            notify=True,
            severity="critical",
            findings=[
                _finding("clamav", "critical", "ClamAV: clamscan found a malicious file in /tmp."),
                _finding("rootkit", "high", "rootkit audit: rkhunter reported a rootkit signature match."),
            ],
        ),
        Scenario(
            id="cross-clean-noise",
            split="train",
            notify=False,
            severity="low",
            findings=[
                _finding("web", "low", "web log audit: a scanner user-agent probed the site."),
                _finding("auth", "low", "authentication log audit: a single failed SSH login."),
                _finding(
                    "network",
                    "low",
                    "network audit: an established outbound connection to the package mirror.",
                ),
            ],
        ),
        Scenario(
            id="cross-coverage-loss",
            split="valid",
            notify=True,
            severity="high",
            findings=[
                _finding("clamav", "high", "ClamAV: clamscan."),
                _finding("debsums", "high", "debsums: debsums -cs."),
            ],
            statuses={"clamav": "timed_out", "debsums": "failed"},
            notes={
                "clamav": ["the scan exceeded its deadline"],
                "debsums": ["the command failed; see the artifact"],
            },
        ),
        Scenario(
            id="cross-aws-hardening",
            split="test",
            notify=True,
            severity="high",
            findings=[
                _finding("aws", "high", "AWS host audit: EC2 IMDSv1 is enabled."),
                _finding(
                    "hardening",
                    "medium",
                    "host hardening audit: SSH password authentication is enabled.",
                ),
            ],
        ),
        Scenario(
            id="cross-persistence-network",
            split="train",
            notify=True,
            severity="critical",
            findings=[
                _finding("persistence", "critical", "persistence audit: a non-root account has UID 0."),
                _finding(
                    "network",
                    "high",
                    "network audit: pending Debian/Ubuntu security updates include OpenSSL.",
                ),
            ],
        ),
        Scenario(
            id="cross-expected-warnings",
            split="train",
            notify=False,
            severity="medium",
            findings=[
                _finding(
                    "docker",
                    "low",
                    "Docker audit: a stopped container has no restart policy.",
                ),
                _finding(
                    "debsums",
                    "medium",
                    "debsums: a locally customized conffile differs from the package default.",
                ),
                _finding(
                    "aws",
                    "info",
                    "AWS host audit: the CloudWatch agent is installed but not running on a non-monitoring host.",
                ),
            ],
        ),
        Scenario(
            id="cross-truncated-context",
            split="train",
            notify=True,
            severity="high",
            findings=[
                _finding("web", "high", "web log audit: SQL injection attempts target the login endpoint."),
            ],
            notes={
                "web": [
                    "long request samples were omitted from the compact context",
                    "the full artifact contains the matched request lines",
                ]
            },
            truncate_at=1200,
        ),
        Scenario(
            id="cross-optional-skips",
            split="train",
            notify=False,
            severity="info",
            statuses={"docker": "skipped", "clamav": "skipped", "debsums": "skipped"},
            notes={
                "docker": ["docker is not installed on this host"],
                "clamav": ["clamscan is not installed on this host"],
                "debsums": ["debsums is not installed on this host"],
            },
        ),
        Scenario(
            id="cross-medium-mixed",
            split="valid",
            notify=True,
            severity="medium",
            findings=[
                _finding("auth", "medium", "authentication log audit: sudo denials were recorded for an unexpected user."),
                _finding("web", "low", "web log audit: a scanner user-agent probed the site."),
            ],
        ),
        Scenario(
            id="cross-severity-ladder",
            split="valid",
            notify=True,
            severity="high",
            findings=[
                _finding("precheck", "info", "dpkg/apt precheck: audit packages are current."),
                _finding("network", "low", "network audit: an established outbound connection to the package mirror."),
                _finding("docker", "medium", "Docker audit: a container runs as root with no-new-privileges disabled."),
                _finding("rootkit", "high", "rootkit audit: chkrootkit reported a suspicious hidden process."),
            ],
        ),
        Scenario(
            id="cross-aws-credentials",
            split="test",
            notify=True,
            severity="critical",
            findings=[
                _finding(
                    "aws",
                    "critical",
                    "AWS host audit: long-term AWS credentials are stored in world-readable user-data.",
                ),
                _finding("aws", "high", "AWS host audit: EC2 IMDSv1 is enabled."),
            ],
        ),
        Scenario(
            id="cross-hardening-accounts",
            split="test",
            notify=True,
            severity="critical",
            findings=[
                _finding("hardening", "critical", "host hardening audit: the root account has an empty password."),
                _finding("persistence", "high", "persistence audit: a non-root account has UID 0."),
            ],
        ),
    ]


def build_context(scenario: Scenario) -> str:
    stages = []
    findings = []
    for stage, title in STAGES:
        stage_findings = [finding for finding in scenario.findings if finding.stage == stage]
        status = scenario.statuses.get(
            stage, "warnings" if stage_findings else "passed"
        )
        highest = max(
            (finding.severity for finding in stage_findings),
            default="info",
            key=SEVERITY_RANK.__getitem__,
        )
        stages.append(
            {
                "title": title,
                "status": status,
                "highest_severity": highest,
                "findings": len(stage_findings),
                "notes": scenario.notes.get(stage, []),
            }
        )
        findings.extend(
            {
                "stage": title,
                "severity": finding.severity,
                "message": finding.message,
            }
            for finding in stage_findings
        )

    counts = {
        severity: sum(1 for finding in scenario.findings if finding.severity == severity)
        for severity in sorted(SEVERITIES)
    }
    highest = max(
        (finding.severity for finding in scenario.findings),
        default="info",
        key=SEVERITY_RANK.__getitem__,
    )
    context = {
        "host": scenario.host,
        "started_at": STARTED_AT,
        "highest_severity": highest,
        "total_findings": len(scenario.findings),
        "finding_counts": counts,
        "stages": stages,
        "findings": findings,
    }
    text = json.dumps(context, indent=2, ensure_ascii=False)
    if scenario.truncate_at is not None:
        encoded = text.encode("utf-8")
        if len(encoded) > scenario.truncate_at:
            text = (
                encoded[: scenario.truncate_at].decode("utf-8", errors="ignore")
                + "\n[context truncated]"
            )
    return text


def expected_labels(scenario: Scenario) -> dict[str, str]:
    """The choice labels for the runtime questions, in option-label form (not booleans)."""
    return {
        "notify": "true" if scenario.notify else "false",
        "severity": scenario.severity,
    }


def scenario_record(scenario: Scenario) -> dict:
    return {
        "id": scenario.id,
        "split": scenario.split,
        "stage": _scenario_stage(scenario),
        "state": build_context(scenario),
        "questions": QUESTIONS,
        "expected": expected_labels(scenario),
    }


def _scenario_stage(scenario: Scenario) -> str:
    stages = {finding.stage for finding in scenario.findings}
    if len(stages) == 1:
        return next(iter(stages))
    if not stages:
        # Clean scenarios have no findings; keep them attributed to their own stage.
        prefix = scenario.id.split("-", 1)[0]
        if prefix in STAGE_TITLES:
            return prefix
    return "multi-stage"


def all_scenarios() -> list[Scenario]:
    scenarios = _stage_scenarios() + _cross_stage_scenarios()
    # A distinct host keeps otherwise-identical clean contexts (and their states) unique.
    for scenario in scenarios:
        if scenario.host == "audit-host":
            scenario.host = f"{scenario.id}-host"
    ids = [scenario.id for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate scenario ids")
    for scenario in scenarios:
        if scenario.split not in {"train", "valid", "test"}:
            raise ValueError(f"{scenario.id}: invalid split {scenario.split}")
        if scenario.severity not in SEVERITIES:
            raise ValueError(f"{scenario.id}: invalid severity {scenario.severity}")
        for stage, status in scenario.statuses.items():
            if stage not in STAGE_TITLES:
                raise ValueError(f"{scenario.id}: unknown stage {stage!r}")
            if status not in STATUSES:
                raise ValueError(f"{scenario.id}: invalid status {status!r}")
        highest = max(
            (finding.severity for finding in scenario.findings),
            default="info",
            key=SEVERITY_RANK.__getitem__,
        )
        if scenario.severity != highest:
            raise ValueError(
                f"{scenario.id}: severity {scenario.severity} does not match the highest "
                f"finding severity {highest}"
            )
        if scenario.notify and scenario.severity in {"info", "low"}:
            raise ValueError(f"{scenario.id}: {scenario.severity} findings must not notify")
        if not scenario.notify and scenario.severity in {"high", "critical"}:
            raise ValueError(f"{scenario.id}: {scenario.severity} findings must notify")
    return scenarios


def questions_document() -> str:
    return json.dumps(QUESTIONS, indent=2, ensure_ascii=False) + "\n"


def build_manifest(scenarios: list[Scenario]) -> dict:
    def distribution(records: list[Scenario], key) -> dict[str, int]:
        result: dict[str, int] = {}
        for record in records:
            value = key(record)
            result[value] = result.get(value, 0) + 1
        return dict(sorted(result.items()))

    splits = {}
    for split in ["train", "valid", "test"]:
        records = [scenario for scenario in scenarios if scenario.split == split]
        splits[split] = {
            "count": len(records),
            "notify": distribution(records, lambda record: "true" if record.notify else "false"),
            "severity": distribution(records, lambda record: record.severity),
            "stage": distribution(records, _scenario_stage),
        }

    return {
        "schema_version": 2,
        "state_format": "audit-context-json",
        "questions_sha256": hashlib.sha256(questions_document().encode("utf-8")).hexdigest(),
        "total": len(scenarios),
        "splits": splits,
        "labels": {
            "notify": distribution(scenarios, lambda record: "true" if record.notify else "false"),
            "severity": distribution(scenarios, lambda record: record.severity),
        },
    }


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DATA_DIR)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the generated files differ from the files on disk",
    )
    args = parser.parse_args()

    scenarios = all_scenarios()
    splits = {
        split: [scenario for scenario in scenarios if scenario.split == split]
        for split in ["train", "valid", "test"]
    }

    generated: dict[Path, str] = {}
    generated[args.out_dir / "questions.json"] = questions_document()
    for split, records in splits.items():
        generated[args.out_dir / f"{split}.jsonl"] = "".join(
            json.dumps(scenario_record(scenario), ensure_ascii=False) + "\n"
            for scenario in records
        )

    generated[args.out_dir / "catalog.jsonl"] = "".join(
        json.dumps(
            {
                "id": scenario.id,
                "split": scenario.split,
                "stage": _scenario_stage(scenario),
                "notify": "true" if scenario.notify else "false",
                "severity": scenario.severity,
                "statuses": scenario.statuses,
                "findings": [
                    {
                        "stage": finding.stage,
                        "severity": finding.severity,
                        "message": finding.message,
                    }
                    for finding in scenario.findings
                ],
            },
            ensure_ascii=False,
        )
        + "\n"
        for scenario in scenarios
    )
    generated[args.out_dir / "manifest.json"] = (
        json.dumps(build_manifest(scenarios), indent=2, sort_keys=True) + "\n"
    )

    if args.check:
        mismatches = [
            path
            for path, content in generated.items()
            if not path.exists() or path.read_text(encoding="utf-8") != content
        ]
        if mismatches:
            for path in mismatches:
                print(f"out of date: {path}")
            return 1
        print(f"dataset is up to date ({len(scenarios)} scenarios)")
        return 0

    for path, content in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    print(f"wrote {len(scenarios)} scenarios to {args.out_dir}")
    for split, records in splits.items():
        print(f"  {split}: {len(records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
