#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
python3 src/case_investigator.py \
  --case-dir cases/synthetic-sift/evidence/sample-case \
  --out-dir cases/synthetic-sift/analysis

python3 src/agentic_runner.py \
  --case-dir cases/synthetic-sift/evidence/sample-case \
  --out-dir cases/synthetic-sift/analysis-agentic
