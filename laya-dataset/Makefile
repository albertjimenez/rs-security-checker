PYTHON ?= python3
MODEL_ID ?= convaiinnovations/laya-multilingual
MODEL_DIR ?=
OUTPUT_DIR ?= ../models/laya-security
DATA ?= data/train.jsonl
EVAL_DATA ?= data/valid.jsonl
EPOCHS ?= 4
MICRO_BATCH ?= 2
GRAD_ACCUM ?= 16
CALIB_MAX ?= 400
MAX_LEN ?= 8192
HEAD_MAX_LEN ?= 256
LOSS ?= rlcd
SEED ?= 42
DEVICE ?= auto
LIMIT ?=
FORCE ?=

MODEL_DIR_ARG = $(if $(MODEL_DIR),--model-dir $(MODEL_DIR),)
LIMIT_ARG = $(if $(LIMIT),--limit $(LIMIT),)
FORCE_ARG = $(if $(FORCE),--force,)

.PHONY: help dataset check validate finetune-setup finetune-check finetune-dry-run finetune clean

help:
	@echo "make dataset         regenerate data/*.jsonl from tools/build_dataset.py"
	@echo "make check           fail if the committed dataset is out of date"
	@echo "make validate        validate the typed rows, labels and question contract"
	@echo "make finetune-setup  install the training dependencies"
	@echo "make finetune-check  validate the data and print the planned fine-tuning run"
	@echo "make finetune-dry-run download the base and tokenize the rows without training"
	@echo "make finetune        fine-tune $(MODEL_ID) on $(DATA)"

dataset:
	$(PYTHON) tools/build_dataset.py

check:
	$(PYTHON) tools/build_dataset.py --check

validate:
	$(PYTHON) tools/validate_dataset.py

finetune-setup:
	$(PYTHON) -m pip install -r requirements-train.txt

finetune-check:
	$(PYTHON) tools/finetune.py --check --data $(DATA) --eval-data $(EVAL_DATA)

finetune-dry-run:
	$(PYTHON) tools/finetune.py --dry-run \
		--model-id $(MODEL_ID) $(MODEL_DIR_ARG) \
		--data $(DATA) --eval-data $(EVAL_DATA) \
		--epochs $(EPOCHS) --micro-batch $(MICRO_BATCH) --grad-accum $(GRAD_ACCUM) \
		--calib-max $(CALIB_MAX) --max-len $(MAX_LEN) --head-max-len $(HEAD_MAX_LEN) \
		--loss $(LOSS) --seed $(SEED) --device $(DEVICE) $(LIMIT_ARG)

finetune:
	$(PYTHON) tools/finetune.py \
		--model-id $(MODEL_ID) $(MODEL_DIR_ARG) \
		--data $(DATA) --eval-data $(EVAL_DATA) --output-dir $(OUTPUT_DIR) \
		--epochs $(EPOCHS) --micro-batch $(MICRO_BATCH) --grad-accum $(GRAD_ACCUM) \
		--calib-max $(CALIB_MAX) --max-len $(MAX_LEN) --head-max-len $(HEAD_MAX_LEN) \
		--loss $(LOSS) --seed $(SEED) --device $(DEVICE) $(LIMIT_ARG) $(FORCE_ARG)

clean:
	rm -rf tools/__pycache__ __pycache__
