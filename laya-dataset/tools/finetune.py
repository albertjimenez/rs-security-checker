#!/usr/bin/env python3
"""Fine-tune a Laya checkpoint on the security-triage dataset.

This is a thin wrapper around ``laya.train.finetune``. It validates the checked-in splits,
downloads the base checkpoint once, trains on ``data/train.jsonl``, evaluates on
``data/valid.jsonl`` and scores the held-out ``data/test.jsonl`` after training.

The default base is ``convaiinnovations/laya-multilingual`` (mmBERT-base, 322M parameters), so
the result can read the same audit contexts in 100+ languages. The output directory has the
standard Laya layout and can be loaded by the checker with ``--laya-model``.

Examples::

    # Validate the dataset and print the planned run; no third-party packages required.
    python3 tools/finetune.py --check

    # Download the base and tokenize the rows without training.
    python3 tools/finetune.py --dry-run

    # Fine-tune on Apple Silicon (MPS) with the defaults.
    python3 tools/finetune.py

    # A short smoke run.
    python3 tools/finetune.py --epochs 1 --micro-batch 2 --grad-accum 8 --limit 8
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
DEFAULT_DATA = ROOT / "data" / "train.jsonl"
DEFAULT_EVAL = ROOT / "data" / "valid.jsonl"
DEFAULT_TEST = ROOT / "data" / "test.jsonl"
DEFAULT_MODEL_ID = "convaiinnovations/laya-multilingual"
DEFAULT_MODELS_DIR = REPO / "models"
DEFAULT_OUTPUT = DEFAULT_MODELS_DIR / "laya-security"
ALLOW_PATTERNS = [
    "rl_agent_config.json",
    "config.json",
    "model.safetensors",
    "tokenizer/*",
    "encoder/*",
]


def load_rows(path: Path) -> list[dict]:
    """Read one JSONL split and fail with the offending line number."""
    path = path.expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"missing dataset file: {path}")

    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: row must be a JSON object")
            rows.append(row)

    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def check_rows(rows: list[dict], path: Path) -> None:
    """Check the fields ``laya.train`` needs before any dependency is imported."""
    for index, row in enumerate(rows, start=1):
        where = f"{path}:{index}"
        state = row.get("state")
        if not isinstance(state, str) or not state.strip():
            raise ValueError(f"{where}: state must be a non-empty JSON string")
        questions = row.get("questions")
        if not isinstance(questions, dict) or not questions:
            raise ValueError(f"{where}: questions must be a non-empty object")
        expected = row.get("expected")
        if not isinstance(expected, dict) or not expected:
            raise ValueError(f"{where}: expected must be a non-empty object")
        unknown = sorted(set(expected) - set(questions))
        if unknown:
            raise ValueError(f"{where}: expected has no matching question(s): {unknown}")


def run_dataset_validator() -> None:
    """Run the full generator/schema/split validator."""
    validator = ROOT / "tools" / "validate_dataset.py"
    result = subprocess.run([sys.executable, str(validator)], check=False)
    if result.returncode != 0:
        raise RuntimeError(f"dataset validation failed (exit {result.returncode})")


def label_counts(rows: list[dict]) -> tuple[str, str]:
    notify = Counter(row["expected"].get("notify") for row in rows)
    severity = Counter(row["expected"].get("severity") for row in rows)
    return (
        ", ".join(
            f"{key}={value}"
            for key, value in sorted(notify.items(), key=lambda item: str(item[0]))
        ),
        ", ".join(
            f"{key}={value}"
            for key, value in sorted(severity.items(), key=lambda item: str(item[0]))
        ),
    )


def resolve_model_dir(
    model_id: str,
    explicit: Path | None,
    models_dir: Path,
    need_weights: bool,
) -> Path:
    """Return a local checkpoint directory, downloading the Hub base when needed."""
    required = ["rl_agent_config.json"]
    if need_weights:
        required.append("model.safetensors")

    if explicit is not None:
        path = explicit.expanduser().resolve()
        missing = [name for name in required if not (path / name).is_file()]
        if missing:
            raise FileNotFoundError(
                f"{path} is not a Laya checkpoint (missing {', '.join(missing)})"
            )
        return path

    local = Path(model_id).expanduser()
    if local.is_dir():
        missing = [name for name in required if not (local / name).is_file()]
        if missing:
            raise FileNotFoundError(
                f"{local} is not a Laya checkpoint (missing {', '.join(missing)})"
            )
        return local.resolve()

    target = models_dir.expanduser() / model_id.rstrip("/").rsplit("/", 1)[-1]
    if all((target / name).is_file() for name in required):
        print(f"using base checkpoint: {target}", flush=True)
        return target

    try:
        from huggingface_hub import snapshot_download
    except ImportError as error:
        raise ImportError(
            "huggingface_hub is required to download the base checkpoint"
        ) from error

    patterns = ALLOW_PATTERNS if need_weights else [
        name for name in ALLOW_PATTERNS if name != "model.safetensors"
    ]
    print(f"downloading {model_id} to {target} ...", flush=True)
    target.mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=model_id,
        local_dir=str(target),
        allow_patterns=patterns,
        token=os.environ.get("HF_TOKEN") or None,
    )

    missing = [name for name in required if not (target / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"{model_id} did not provide {', '.join(missing)} in {target}"
        )
    return target


def build_config(args: argparse.Namespace):
    from laya.train import TrainConfig

    return TrainConfig(
        epochs=args.epochs,
        micro_batch=args.micro_batch,
        grad_accum=args.grad_accum,
        encoder_lr=args.encoder_lr,
        head_lr=args.head_lr,
        loss=args.loss,
        label_smoothing=args.label_smoothing,
        shuffle_options=("choice",) if args.shuffle_options else (),
        freeze_encoder=args.freeze_encoder,
        calib_max=args.calib_max,
        seed=args.seed,
        max_len=args.max_len,
        head_max_len=args.head_max_len,
        eval_data=None if args.no_eval else str(args.eval_data),
        target_error=args.target_error,
        min_abstain_n=args.min_abstain_n,
        log_every=args.log_every,
    )


@contextmanager
def limited_rows(path: Path, limit: int | None):
    """Yield the original path, or a temporary JSONL with the first ``limit`` rows."""
    if limit is None:
        yield path
        return
    if limit < 1:
        raise ValueError("--limit must be a positive integer")

    rows = load_rows(path)
    selected = rows[:limit]
    fd, name = tempfile.mkstemp(prefix="laya-train-", suffix=".jsonl")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for row in selected:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"smoke run: using {len(selected)} of {len(rows)} training rows", flush=True)
        yield Path(name)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def evaluate_test(
    rows: list[dict],
    checkpoint: Path,
    device: str,
    max_len: int,
) -> tuple[int, int]:
    """Score the held-out test split with the saved checkpoint."""
    import laya

    agent = laya.load(str(checkpoint), device=None if device == "auto" else device)
    correct = total = 0
    for row in rows:
        result = agent.predict(row["state"], row["questions"], max_len=max_len)
        for question_id, answer in (result.get("answers") or {}).items():
            expected = row["expected"].get(question_id)
            if expected is None:
                continue
            if isinstance(answer, dict):
                predicted = answer.get("choice", answer.get("label"))
            else:
                predicted = answer
            if predicted is None:
                continue
            total += 1
            correct += str(predicted).lower() == str(expected).lower()
    return correct, total


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA, help="training JSONL")
    parser.add_argument(
        "--eval-data",
        type=Path,
        default=DEFAULT_EVAL,
        help="held-out JSONL used for the before/after report",
    )
    parser.add_argument(
        "--test-data",
        type=Path,
        default=DEFAULT_TEST,
        help="held-out JSONL scored after training (default: data/test.jsonl)",
    )
    parser.add_argument(
        "--model-id",
        default=DEFAULT_MODEL_ID,
        help=f"Hub checkpoint or local path (default: {DEFAULT_MODEL_ID})",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=None,
        help="existing local base checkpoint; skips the download",
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=DEFAULT_MODELS_DIR,
        help=f"where downloaded bases are stored (default: {DEFAULT_MODELS_DIR})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"fine-tuned checkpoint directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--micro-batch", type=int, default=2)
    parser.add_argument("--grad-accum", type=int, default=16)
    parser.add_argument("--encoder-lr", type=float, default=2.5e-5)
    parser.add_argument("--head-lr", type=float, default=1e-4)
    parser.add_argument("--loss", choices=("rlcd", "soft-ce"), default="rlcd")
    parser.add_argument("--label-smoothing", type=float, default=0.0)
    parser.add_argument(
        "--shuffle-options",
        action="store_true",
        help="augment choice questions with random option order",
    )
    parser.add_argument(
        "--freeze-encoder",
        action="store_true",
        help="train the classification heads only",
    )
    parser.add_argument("--calib-max", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-len", type=int, default=8192)
    parser.add_argument("--head-max-len", type=int, default=256)
    parser.add_argument("--target-error", type=float, default=0.10)
    parser.add_argument("--min-abstain-n", type=int, default=10)
    parser.add_argument(
        "--device",
        choices=("auto", "mps", "cpu", "cuda"),
        default="auto",
    )
    parser.add_argument("--log-every", type=int, default=10)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="train on the first N rows only (smoke tests; not a full run)",
    )
    parser.add_argument(
        "--no-eval",
        action="store_true",
        help="skip the held-out valid.jsonl report",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="skip scoring data/test.jsonl after training",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the dataset and print the planned run; no training",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="tokenize the rows and report item counts without training",
    )
    parser.add_argument(
        "--download-only",
        action="store_true",
        help="download the base checkpoint and exit",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite a non-empty output directory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.data = args.data.expanduser()
    args.eval_data = args.eval_data.expanduser()
    args.test_data = args.test_data.expanduser()
    args.output_dir = args.output_dir.expanduser().resolve()

    try:
        train_rows = load_rows(args.data)
        check_rows(train_rows, args.data)
        eval_rows = [] if args.no_eval else load_rows(args.eval_data)
        if eval_rows:
            check_rows(eval_rows, args.eval_data)
        test_rows = [] if args.no_test else load_rows(args.test_data)
        if test_rows:
            check_rows(test_rows, args.test_data)

        if args.check:
            run_dataset_validator()
            notify, severity = label_counts(train_rows)
            print(
                f"train: {len(train_rows)} rows (notify: {notify}; severity: {severity})"
            )
            if eval_rows:
                notify, severity = label_counts(eval_rows)
                print(
                    f"eval:  {len(eval_rows)} rows (notify: {notify}; severity: {severity})"
                )
            if test_rows:
                notify, severity = label_counts(test_rows)
                print(
                    f"test:  {len(test_rows)} rows (notify: {notify}; severity: {severity})"
                )
            print(f"base:  {args.model_id}")
            print(f"out:   {args.output_dir}")
            print(
                "plan:  "
                f"epochs={args.epochs} micro_batch={args.micro_batch} "
                f"grad_accum={args.grad_accum} loss={args.loss} "
                f"max_len={args.max_len} device={args.device}"
            )
            return 0

        run_dataset_validator()
        need_weights = not args.dry_run
        model_dir = resolve_model_dir(
            args.model_id,
            args.model_dir,
            args.models_dir,
            need_weights=need_weights,
        )
        if args.download_only:
            print(f"base checkpoint ready: {model_dir}")
            return 0

        from laya.train import dry_run, finetune

        config = build_config(args)
        if args.dry_run:
            with limited_rows(args.data, args.limit) as data_path:
                summary = dry_run(str(data_path), str(model_dir), config)
            print(json.dumps(summary, indent=2, default=str))
            return 0

        if args.output_dir.exists() and any(args.output_dir.iterdir()) and not args.force:
            raise FileExistsError(
                f"{args.output_dir} is not empty; pass --force to overwrite it"
            )

        with limited_rows(args.data, args.limit) as data_path:
            summary = finetune(
                data=str(data_path),
                model_dir=str(model_dir),
                output_dir=str(args.output_dir),
                config=config,
                device=args.device,
            )

        report = summary.get("train_report") or {}
        before = report.get("before") or {}
        after = report.get("after") or {}
        print("\nFine-tuning complete.")
        print(f"  checkpoint: {summary['output_dir']}")
        print(
            "  items: "
            f"train={summary['train_items']} "
            f"calibration={summary['calibration_items']} "
            f"eval={summary['eval_items']}"
        )
        if before and after:
            print(
                "  valid accuracy: "
                f"{before.get('accuracy', float('nan')):.4f} -> "
                f"{after.get('accuracy', float('nan')):.4f}"
            )
        if test_rows:
            correct, total = evaluate_test(
                test_rows,
                args.output_dir,
                args.device,
                args.max_len,
            )
            if total:
                print(f"  test accuracy: {correct}/{total} = {correct / total:.4f}")
        if summary.get("skipped"):
            print(f"  skipped rows: {summary['skipped']}")
        print(
            "\nLoad it with:\n"
            f"  cargo run --release --all-features -- --laya "
            f"--laya-model {summary['output_dir']}"
        )
        return 0
    except ImportError as error:
        print(f"error: missing training dependency: {error}", file=sys.stderr)
        print(
            "  python3 -m pip install -r laya-dataset/requirements-train.txt",
            file=sys.stderr,
        )
        return 1
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
