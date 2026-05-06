#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
python3 src/benchmark_runner.py \
  --case-dir cases/dfir-metric-web-obfuscation/evidence/dfir-metric-web-obfuscation \
  --out-dir cases/dfir-metric-web-obfuscation/analysis-agentic
