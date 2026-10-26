# laya security-triage dataset

This folder contains the labelled typed-decision dataset for the **System One** Laya model that the
checker runs in-process with `--laya-api laya`. It also contains a thin fine-tuning wrapper around
Laya's `laya.train.finetune`; the training loop, calibration and export stay in the upstream `laya`
package.

The model never generates text: it receives the same compact audit context the checker builds and
scores two typed questions.

| question | type | options |
|---|---|---|
| `notify` | choice | `true`, `false` |
| `severity` | choice | `info`, `low`, `medium`, `high`, `critical` |

The runtime reads the winning labels directly (`src/laya/mod.rs`), so the dataset is a set of
labelled decisions, not prompts and completions.

## Row format

Every row in `data/{train,valid,test}.jsonl` is one typed-decision case:

```json
{
  "id": "network-high",
  "split": "train",
  "stage": "network",
  "state": "{\n  \"host\": \"network-high-host\",\n  ...\n}",
  "questions": {
    "notify": {
      "type": "choice",
      "instructions": "Does this audit warrant notifying the on-call engineer?",
      "criteria": ["true", "false"]
    },
    "severity": {
      "type": "choice",
      "instructions": "What is the highest triage severity warranted by this audit?",
      "criteria": ["info", "low", "medium", "high", "critical"]
    }
  },
  "expected": {"notify": "true", "severity": "high"}
}
```

* `state` is the pretty-printed audit context produced by `build_context()`: host, start time,
  highest severity, finding counts, one entry per stage (title, status, highest severity, finding
  count, notes) and up to 40 findings.
* `questions` is identical in every row and identical to `data/questions.json`.
* `expected.notify` is the **string choice label** `"true"` or `"false"`. It is not a boolean,
  because the target is matched against the question's `criteria`. `expected.severity` is one of
  the five severity labels.

## Label policy

The labels follow the checker's triage rules:

* `info` and `low` findings never notify; `high` and `critical` findings always do.
* `medium` findings notify when they need an operator decision (for example a container running
  as root with `no-new-privileges` disabled) and stay quiet when they are expected on the host
  (for example a vendor sysctl override).
* A stage that **failed** or **timed out** lost coverage and must notify, because the audit
  cannot claim the host is clean. A **skipped** stage is an unavailable optional tool and does
  not by itself force a notification.
* The expected severity equals the highest finding severity in the state.

`tools/validate_dataset.py` enforces all of the above.

## Composition

`tools/build_dataset.py` is the source of truth. It emits **100 scenarios**:

* 11 stages × 8 variants: clean, low noise, expected medium, actionable medium, high, critical,
  coverage failed, coverage timed out.
* 12 cross-stage scenarios: malware plus rootkit, clean noise, coverage loss, AWS plus hardening,
  persistence plus network, expected warnings, truncated context, optional skips, medium mix,
  severity ladder, AWS credentials, hardening plus accounts.

The split is deterministic: **72 train / 14 valid / 14 test**. No state appears in more than one
split. `catalog.jsonl` records the id, split, stage, labels and findings of every scenario, and
`manifest.json` records the counts, label distributions and a hash of the question contract.

## Layout

```text
laya-dataset/
├── data/
│   ├── train.jsonl       # 72 typed decisions
│   ├── valid.jsonl       # 14 typed decisions
│   ├── test.jsonl        # 14 held-out typed decisions
│   ├── questions.json    # the runtime question contract
│   ├── catalog.jsonl     # one line per scenario: id, split, stage, labels, findings
│   └── manifest.json     # counts, distributions, question hash
├── tools/
│   ├── build_dataset.py  # generator; mirrors src/laya/mod.rs
│   ├── validate_dataset.py
│   ├── summary_to_record.py
│   └── finetune.py       # thin wrapper around laya.train.finetune
├── requirements-train.txt
└── Makefile
```

## Regenerate and validate

```bash
make dataset        # rewrite data/*.jsonl, questions.json, catalog and manifest
make check          # fail if the committed files differ from the generator
make validate       # schema, labels, context structure and split invariants
```

`make check` and `make validate` also run in CI. The `questions.json` file is compared with
`laya_questions()` in `src/laya/mod.rs` by a Rust unit test, so changing a question in either
place fails the build.

## Fine-tune the multilingual base

`tools/finetune.py` is a thin wrapper around `laya.train.finetune`. It validates the splits,
downloads `convaiinnovations/laya-multilingual` once, trains on `data/train.jsonl`, evaluates on
`data/valid.jsonl`, and writes a standard Laya checkpoint. The training loop, RLCD objective,
temperature calibration and checkpoint export are upstream code; this repository supplies the data
and the orchestration.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-train.txt

make finetune-check      # validate the data and print the planned run; no model needed
make finetune-dry-run    # download the base/tokenizer and report item counts
make finetune            # writes ../models/laya-security
```

The default base is the multilingual checkpoint. Use the English checkpoint with
`make finetune MODEL_ID=convaiinnovations/laya`, or point at an existing local checkpoint with
`MODEL_DIR=/path/to/laya-base`. Override hyperparameters as Make variables, for example:

```bash
make finetune EPOCHS=1 MICRO_BATCH=2 GRAD_ACCUM=8 DEVICE=mps LIMIT=8 FORCE=1
```

`LIMIT` trains on the first N rows only; it is for smoke tests. A full run uses all 72 training
rows. `make finetune` refuses to overwrite a non-empty output directory unless `FORCE=1` is set.
The wrapper trains at 8,192 tokens, matching the checker's runtime budget. That matters: the
largest row is only ~2,600 characters, but its tokenizer count is around 1,000 tokens, and the
question head leaves less room at 1,024, so a 1,024-token run would silently truncate some states.
`data/test.jsonl` is scored after training and is not used for calibration or model selection.

The result is loadable by the checker:

```bash
cargo run --release --all-features -- --laya --laya-model models/laya-security
```

## Turn a real audit into a dataset row

```bash
# Print the typed record without a label
python3 tools/summary_to_record.py --summary reports/audit-summary.json

# Append an analyst-confirmed row to a separate file
python3 tools/summary_to_record.py --summary reports/audit-summary.json \
    --id prod-web-01 --notify true --severity high --output data/extra.jsonl
```

`--label '{"notify": true, "severity": "high"}'` is accepted too, and a boolean `notify` is
normalised to the string label. The converter rebuilds the state with the same 40-finding and
400-character caps and the default 21,000-character budget as the checker, so the row looks like
the generated splits. Keep extra rows out of the generated files: `build_dataset.py` owns
`data/train.jsonl`, `data/valid.jsonl` and `data/test.jsonl`, and `make check` would overwrite
them.

## Use a checkpoint with the checker

```bash
cargo run --release --all-features -- --laya --laya-model models/laya-security
```

The checkpoint layout is the standard Laya one, so `--laya-api laya` loads it in-process. The
checker raises the checkpoint's 512–1,024-token budget to 8,192 by default and preflights the
context with a tokenizer-free estimate: it warns at 90% of the state budget and records a
`laya_error` rather than let the model truncate the context. The generated rows are roughly
700–900 tokens, so they fit both limits.

The optional `--laya-api openai` backend is unrelated to this dataset and still expects a
generative model server.
