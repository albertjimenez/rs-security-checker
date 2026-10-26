#!/usr/bin/env python3
"""Validate the Laya System One security-triage dataset.

Checks performed:

* every JSONL row carries a non-empty ``state``, the runtime ``questions`` and one
  ``expected`` label per question;
* the questions match the checked-in ``data/questions.json``, which a Rust test compares with
  ``laya_questions()`` in ``src/laya/mod.rs``;
* the state parses as the same audit context the checker builds, with consistent counts,
  stage statuses and highest severity;
* ``notify`` is the string choice label ``"true"``/``"false"`` (not a boolean), and the
  label policy matches the runtime rules;
* split sizes, ids, the catalog and ``manifest.json`` agree with the generator;
* every state fits the runtime's 8,192-token Laya budget under the same naive estimate;
* no state is reused across splits.

Run from anywhere:

    python3 laya-dataset/tools/validate_dataset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
SPLITS = ("train", "valid", "test")
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}
STATUSES = {"passed", "warnings", "failed", "skipped", "timed_out"}
MAX_CONTEXT_FINDINGS = 40
TRUNCATION_MARKER = "\n[context truncated]"
# Keep these in sync with `constants.rs`: the runtime raises the checkpoint's 512–1,024-token
# budget to 8,192 and rejects a context that would not fit.
MAX_SEQUENCE_TOKENS = 8_192
HEAD_TOKEN_RESERVE = 256 + 8
BYTES_PER_TOKEN = 3
TOKEN_SAFETY_PERCENT = 10
STATE_TOKEN_BUDGET = MAX_SEQUENCE_TOKENS - HEAD_TOKEN_RESERVE

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_dataset import (  # noqa: E402
    QUESTIONS,
    STAGE_TITLES,
    all_scenarios,
    build_manifest,
    questions_document,
)


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"{path.name}:{line_number}: invalid JSON: {error}") from error
    return records


def estimate_tokens(text: str) -> int:
    """Tokenizer-free token estimate, matching the runtime guard in `src/laya/mod.rs`."""
    base = (len(text.encode("utf-8")) + BYTES_PER_TOKEN - 1) // BYTES_PER_TOKEN
    return base + base * TOKEN_SAFETY_PERCENT // 100


def check_expected(record: dict, where: str, errors: list[str]) -> dict | None:
    expected = record.get("expected")
    if not isinstance(expected, dict):
        errors.append(f"{where}: expected must be an object")
        return None
    if set(expected) != set(QUESTIONS):
        errors.append(f"{where}: expected keys must be {sorted(QUESTIONS)}, got {sorted(expected)}")
        return None
    notify = expected.get("notify")
    if not isinstance(notify, str) or notify not in QUESTIONS["notify"]["criteria"]:
        errors.append(
            f"{where}: notify must be the string choice label "
            f"{QUESTIONS['notify']['criteria']}, got {notify!r}"
        )
    severity = expected.get("severity")
    if severity not in QUESTIONS["severity"]["criteria"]:
        errors.append(f"{where}: invalid severity {severity!r}")
    if notify == "true" and severity in {"info", "low"}:
        errors.append(f"{where}: {severity} findings must not notify")
    if notify == "false" and severity in {"high", "critical"}:
        errors.append(f"{where}: {severity} findings must notify")
    return expected


def check_context(
    record: dict,
    expected: dict,
    where: str,
    errors: list[str],
) -> None:
    state = record.get("state")
    if not isinstance(state, str) or not state.strip():
        errors.append(f"{where}: state must be a non-empty JSON string")
        return
    if state.endswith(TRUNCATION_MARKER):
        # Truncated states are intentionally invalid JSON; the model must still triage them.
        return
    try:
        context = json.loads(state)
    except json.JSONDecodeError as error:
        errors.append(f"{where}: state is not valid JSON: {error}")
        return
    if not isinstance(context, dict):
        errors.append(f"{where}: state must decode to an object")
        return

    for key in (
        "host",
        "started_at",
        "highest_severity",
        "total_findings",
        "finding_counts",
        "stages",
        "findings",
    ):
        if key not in context:
            errors.append(f"{where}: state is missing {key!r}")

    stages = context.get("stages", [])
    findings = context.get("findings", [])
    if not isinstance(stages, list) or not isinstance(findings, list):
        errors.append(f"{where}: state stages/findings must be arrays")
        return
    if len(stages) != len(STAGE_TITLES):
        errors.append(f"{where}: state has {len(stages)} stages, expected {len(STAGE_TITLES)}")
    titles = {title for title in STAGE_TITLES.values()}
    for stage in stages:
        if not isinstance(stage, dict):
            errors.append(f"{where}: stage entry must be an object")
            continue
        if stage.get("title") not in titles:
            errors.append(f"{where}: unknown stage title {stage.get('title')!r}")
        if stage.get("status") not in STATUSES:
            errors.append(f"{where}: invalid stage status {stage.get('status')!r}")
        if stage.get("highest_severity") not in SEVERITIES:
            errors.append(f"{where}: invalid stage highest_severity {stage.get('highest_severity')!r}")
        if not isinstance(stage.get("findings"), int) or stage.get("findings") < 0:
            errors.append(f"{where}: stage findings must be a non-negative integer")

    if len(findings) > MAX_CONTEXT_FINDINGS:
        errors.append(
            f"{where}: state carries {len(findings)} findings, but the runtime caps the context "
            f"at {MAX_CONTEXT_FINDINGS}"
        )
    if context.get("total_findings") != len(findings):
        errors.append(f"{where}: total_findings does not match the findings array")
    counts = context.get("finding_counts", {})
    if sum(counts.values()) != context.get("total_findings"):
        errors.append(f"{where}: finding_counts does not sum to total_findings")
    if any(counts.get(severity, 0) != sum(1 for f in findings if f.get("severity") == severity)
           for severity in SEVERITIES):
        errors.append(f"{where}: finding_counts does not match the findings array")

    highest = max(
        (finding.get("severity", "info") for finding in findings),
        default="info",
        key=SEVERITY_RANK.get,
    )
    if context.get("highest_severity") != highest:
        errors.append(
            f"{where}: state highest_severity is {context.get('highest_severity')!r}, "
            f"findings say {highest!r}"
        )
    if expected.get("severity") != highest:
        errors.append(
            f"{where}: expected severity {expected.get('severity')!r} does not match the "
            f"highest finding severity {highest!r}"
        )

    # A failed or timed-out stage means coverage was lost and must be escalated. A skipped
    # stage is an unavailable optional tool, which is not by itself an incident.
    for stage in stages:
        if stage.get("status") in {"failed", "timed_out"} and expected.get("notify") != "true":
            errors.append(
                f"{where}: stage {stage.get('title')!r} is {stage.get('status')} but notify is "
                f"{expected.get('notify')!r}"
            )


def check_catalog(catalog: list[dict], expected: list[dict], errors: list[str]) -> None:
    by_id = {}
    for entry in catalog:
        scenario_id = entry.get("id")
        if scenario_id in by_id:
            errors.append(f"catalog: duplicate id {scenario_id!r}")
        by_id[scenario_id] = entry
    expected_ids = {scenario["id"] for scenario in expected}
    if set(by_id) != expected_ids:
        missing = sorted(expected_ids - set(by_id))
        extra = sorted(set(by_id) - expected_ids)
        errors.append(f"catalog: id mismatch (missing={missing}, extra={extra})")
    for scenario in expected:
        entry = by_id.get(scenario["id"])
        if entry is None:
            continue
        for key in ("split", "notify", "severity"):
            if entry.get(key) != scenario[key]:
                errors.append(
                    f"catalog: {scenario['id']} {key} is {entry.get(key)!r}, "
                    f"expected {scenario[key]!r}"
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()

    errors: list[str] = []
    manifest_path = args.data_dir / "manifest.json"
    catalog_path = args.data_dir / "catalog.jsonl"
    questions_path = args.data_dir / "questions.json"

    if not manifest_path.exists():
        print(f"error: missing {manifest_path}", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema_version") != 2:
        errors.append(f"manifest: schema_version must be 2, got {manifest.get('schema_version')!r}")
    if manifest.get("state_format") != "audit-context-json":
        errors.append("manifest: state_format must be 'audit-context-json'")

    expected_questions = json.loads(questions_document())
    if not questions_path.exists():
        errors.append("missing questions.json")
    else:
        try:
            questions = json.loads(questions_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            errors.append(f"questions.json: invalid JSON: {error}")
        else:
            if questions != expected_questions:
                errors.append("questions.json: content does not match build_dataset.QUESTIONS")

    questions_hash = hashlib.sha256(questions_document().encode("utf-8")).hexdigest()
    if manifest.get("questions_sha256") != questions_hash:
        errors.append("manifest: questions_sha256 does not match build_dataset.QUESTIONS")

    scenarios = all_scenarios()
    expected_manifest = build_manifest(scenarios)
    if manifest != expected_manifest:
        errors.append("manifest: content does not match the current generator")

    records_by_split: dict[str, list[dict]] = {}
    state_hashes: dict[str, str] = {}
    for split in SPLITS:
        path = args.data_dir / f"{split}.jsonl"
        if not path.exists():
            errors.append(f"missing {path.name}")
            continue
        records = load_jsonl(path)
        records_by_split[split] = records
        declared = manifest.get("splits", {}).get(split, {}).get("count")
        if declared != len(records):
            errors.append(f"{split}.jsonl: has {len(records)} records, manifest says {declared}")
        for record in records:
            scenario_id = record.get("id")
            where = f"{split}.jsonl:{scenario_id}"
            if not isinstance(scenario_id, str) or not scenario_id:
                errors.append(f"{where}: missing id")
                continue
            if record.get("split") != split:
                errors.append(f"{where}: split field is {record.get('split')!r}, expected {split!r}")
            if record.get("questions") != expected_questions:
                errors.append(f"{where}: questions do not match data/questions.json")
            expected = check_expected(record, where, errors)
            if expected is None:
                continue
            check_context(record, expected, where, errors)

            state = record.get("state")
            if isinstance(state, str):
                digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
                previous = state_hashes.get(digest)
                if previous is not None:
                    errors.append(f"{where}: duplicate state also used by {previous}")
                else:
                    state_hashes[digest] = f"{split}.jsonl:{scenario_id}"
                estimated = estimate_tokens(state)
                if estimated > STATE_TOKEN_BUDGET:
                    errors.append(
                        f"{where}: state is ~{estimated} tokens, over the "
                        f"{STATE_TOKEN_BUDGET}-token Laya state budget"
                    )

    ids = [record.get("id") for records in records_by_split.values() for record in records]
    if len(ids) != len(set(ids)):
        errors.append("dataset: ids are not unique across splits")

    if catalog_path.exists():
        check_catalog(
            load_jsonl(catalog_path),
            [
                {
                    "id": scenario.id,
                    "split": scenario.split,
                    "notify": "true" if scenario.notify else "false",
                    "severity": scenario.severity,
                }
                for scenario in scenarios
            ],
            errors,
        )
    else:
        errors.append("missing catalog.jsonl")

    if errors:
        print(f"dataset validation failed with {len(errors)} error(s):", file=sys.stderr)
        for error in errors[:100]:
            print(f"  - {error}", file=sys.stderr)
        if len(errors) > 100:
            print(f"  ... and {len(errors) - 100} more", file=sys.stderr)
        return 1

    total = sum(len(records) for records in records_by_split.values())
    counts = ", ".join(f"{split}={len(records_by_split[split])}" for split in SPLITS)
    print(f"dataset OK: {total} scenarios ({counts}); typed questions match data/questions.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
