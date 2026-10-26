#!/usr/bin/env python3
"""Turn a real ``audit-summary.json`` into a Laya typed-decision record.

The record has the same shape as the generated splits::

    {"id": ..., "stage": ..., "state": <audit context JSON>, "questions": {...},
     "expected": {"notify": "true", "severity": "high"}}

Use it to spot-check a checkpoint on a host you operate, or to add analyst-confirmed examples to a
separate JSONL file. Keep extra files out of ``data/train.jsonl``: ``build_dataset.py`` owns the
generated splits.

Examples::

    # Print the typed record without labels
    python3 tools/summary_to_record.py --summary reports/audit-summary.json

    # Append a labelled record for a separate JSONL file
    python3 tools/summary_to_record.py --summary reports/audit-summary.json \
        --id prod-web-01 --notify true --severity high --output data/extra.jsonl

    # The label can also be one JSON object; a boolean notify is normalised to "true"/"false"
    python3 tools/summary_to_record.py --summary reports/audit-summary.json \
        --label '{"notify": false, "severity": "low"}'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_dataset import QUESTIONS, SEVERITIES, SEVERITY_RANK  # noqa: E402

MAX_FINDINGS = 40
MAX_FINDING_CHARS = 400
MAX_CONTEXT_CHARS = 21_000
TRUNCATION_MARKER = "\n[context truncated]"
MAX_SEQUENCE_TOKENS = 8_192
HEAD_TOKEN_RESERVE = 256 + 8
STATE_TOKEN_BUDGET = MAX_SEQUENCE_TOKENS - HEAD_TOKEN_RESERVE
BYTES_PER_TOKEN = 3
TOKEN_SAFETY_PERCENT = 10


def estimate_tokens(text: str) -> int:
    """Tokenizer-free token estimate, matching the runtime guard in `src/laya/mod.rs`."""
    base = (len(text.encode("utf-8")) + BYTES_PER_TOKEN - 1) // BYTES_PER_TOKEN
    return base + base * TOKEN_SAFETY_PERCENT // 100


def truncate(text: str, limit: int) -> str:
    """Byte-oriented truncation, matching the Rust helper on UTF-8 input."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore")


def context_from_summary(summary: dict, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    stages = []
    findings = []
    all_findings = [
        finding
        for stage in summary.get("stages", [])
        for finding in stage.get("findings", [])
    ]
    for stage in summary.get("stages", []):
        stage_findings = stage.get("findings", [])
        highest = max(
            (finding.get("severity", "info") for finding in stage_findings),
            default="info",
            key=SEVERITY_RANK.__getitem__,
        )
        stages.append(
            {
                "title": stage.get("title", ""),
                "status": stage.get("status", "unknown"),
                "highest_severity": highest,
                "findings": len(stage_findings),
                "notes": stage.get("notes", []),
            }
        )
        for finding in stage_findings:
            if len(findings) >= MAX_FINDINGS:
                break
            findings.append(
                {
                    "stage": stage.get("title", ""),
                    "severity": finding.get("severity", "info"),
                    "message": truncate(finding.get("message", ""), MAX_FINDING_CHARS),
                }
            )

    counts = {severity: 0 for severity in sorted(SEVERITIES)}
    for finding in all_findings:
        severity = finding.get("severity", "info")
        counts[severity] = counts.get(severity, 0) + 1

    context = {
        "host": summary.get("host", "unknown"),
        "started_at": summary.get("started_at", ""),
        "highest_severity": summary.get("highest_severity", "info"),
        "total_findings": summary.get("total_findings", len(all_findings)),
        "finding_counts": counts,
        "stages": stages,
        "findings": findings,
    }
    text = json.dumps(context, indent=2, ensure_ascii=False)
    encoded = text.encode("utf-8")
    if len(encoded) > max_chars:
        text = encoded[:max_chars].decode("utf-8", errors="ignore") + TRUNCATION_MARKER
    return text


def normalise_notify(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered
    raise ValueError(f"notify must be a boolean or 'true'/'false', got {value!r}")


def normalise_label(label: dict) -> dict[str, str]:
    if set(label) != {"notify", "severity"}:
        raise ValueError("label must contain exactly notify and severity")
    notify = normalise_notify(label["notify"])
    severity = label["severity"]
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
    if notify == "true" and severity in {"info", "low"}:
        raise ValueError(f"{severity} findings must not notify")
    if notify == "false" and severity in {"high", "critical"}:
        raise ValueError(f"{severity} findings must notify")
    return {"notify": notify, "severity": severity}


def summary_stage(summary: dict) -> str:
    titles = {
        "Precheck & Dependencies": "precheck",
        "Docker Security Audit": "docker",
        "ClamAV Scan": "clamav",
        "Debsums Integrity": "debsums",
        "Rootkit Audits": "rootkit",
        "Persistence & Account Audit": "persistence",
        "Network Sockets & Pending Patches": "network",
        "Web Server Logs": "web",
        "Authentication Logs": "auth",
        "Host Hardening": "hardening",
        "AWS Host & Metadata": "aws",
    }
    with_findings = [
        stage
        for stage in summary.get("stages", [])
        if stage.get("findings")
    ]
    if len(with_findings) == 1:
        return titles.get(with_findings[0].get("title", ""), "multi-stage")
    return "multi-stage" if with_findings else "clean"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True, help="audit-summary.json")
    parser.add_argument("--id", default="real-audit", help="id for the JSONL record")
    parser.add_argument("--label", default=None, help='label object, e.g. \'{"notify": true, "severity": "high"}\'')
    parser.add_argument("--notify", default=None, help="true/false label (alternative to --label)")
    parser.add_argument("--severity", default=None, help="severity label (alternative to --label)")
    parser.add_argument(
        "--max-chars",
        type=int,
        default=MAX_CONTEXT_CHARS,
        help=f"state character budget (default: {MAX_CONTEXT_CHARS}, the checker default)",
    )
    parser.add_argument("--output", type=Path, default=None, help="append JSONL here instead of stdout")
    args = parser.parse_args()

    if not args.summary.exists():
        print(f"error: missing {args.summary}", file=sys.stderr)
        return 2
    try:
        summary = json.loads(args.summary.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        print(f"error: --summary is not valid JSON: {error}", file=sys.stderr)
        return 2
    if not isinstance(summary.get("stages"), list):
        print("error: input does not look like an audit summary", file=sys.stderr)
        return 2

    record = {
        "id": args.id,
        "stage": summary_stage(summary),
        "state": context_from_summary(summary, args.max_chars),
        "questions": QUESTIONS,
    }

    estimated = estimate_tokens(record["state"])
    if estimated > STATE_TOKEN_BUDGET:
        print(
            f"warning: state is ~{estimated} tokens, over the checker's "
            f"{STATE_TOKEN_BUDGET}-token Laya state budget; lower --max-chars",
            file=sys.stderr,
        )
    elif estimated * 100 >= STATE_TOKEN_BUDGET * 90:
        print(
            f"warning: state is ~{estimated} tokens, close to the "
            f"{STATE_TOKEN_BUDGET}-token Laya state budget",
            file=sys.stderr,
        )

    label: dict | None = None
    if args.label is not None:
        if args.notify is not None or args.severity is not None:
            print("error: use either --label or --notify/--severity, not both", file=sys.stderr)
            return 2
        try:
            label = json.loads(args.label)
        except json.JSONDecodeError as error:
            print(f"error: --label is not valid JSON: {error}", file=sys.stderr)
            return 2
        if not isinstance(label, dict):
            print("error: --label must be a JSON object", file=sys.stderr)
            return 2
    elif args.notify is not None or args.severity is not None:
        if args.notify is None or args.severity is None:
            print("error: --notify and --severity must be given together", file=sys.stderr)
            return 2
        label = {"notify": args.notify, "severity": args.severity}

    if label is not None:
        try:
            record["expected"] = normalise_label(label)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

    line = json.dumps(record, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("a", encoding="utf-8") as handle:
            handle.write(line)
        print(f"record appended to {args.output}")
    else:
        sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
