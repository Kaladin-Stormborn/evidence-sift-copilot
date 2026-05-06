# Evidence SIFT Copilot

Evidence SIFT Copilot is a Protocol SIFT-style autonomous DFIR assistant focused on one principle:

> No claim without tool-backed evidence.

The agent chooses an investigation plan, but deterministic read-only tools produce the evidence. The final report includes a claim ledger, command-level audit log, self-correction/refusal behavior, and benchmark scoring against ground truth.

## What It Demonstrates

- SIFT-style case folder workflow.
- Agent-selected, allowlisted investigation plan.
- Deterministic tool execution.
- Evidence-backed report.
- Unsupported-claim refusal.
- DFIR-Metric benchmark solve with ground truth.

## Runs

Judge quickstart:

```bash
python3 -m pytest -q
./run_synthetic.sh
./run_benchmark.sh
```

Synthetic SIFT-style case:

```bash
./run_synthetic.sh
```

DFIR-Metric benchmark case:

```bash
./run_benchmark.sh
```

No Python package install is required for the included demos. The live planner uses `CODEX_BIN` when set, otherwise `codex` from `PATH`; if unavailable, the runners record the planner error and use a deterministic fallback plan for reproducibility.

## Outputs

Each run writes:

- `analysis-agentic/report.md`
- `analysis-agentic/claims.jsonl`
- `analysis-agentic/audit-log.jsonl`
- `analysis-agentic/plan.jsonl`
- `analysis-agentic/chain-of-custody.jsonl`
- `analysis-agentic/self-correction.md`
- `analysis-agentic/claim-review.raw.txt` for the synthetic agentic run
- `analysis-agentic/agent-planner.raw.txt`

## Benchmarked Result

DFIR-Metric web obfuscation benchmark:

- Produced answer: `<xml>10.12.19.134</xml>`
- Ground truth: `<xml>10.12.19.134</xml>`
- Test suite: `3 passed in 0.03s`

## Guardrails

- Evidence files are read-only.
- Tool choices are allowlisted.
- Model output is validated before execution.
- Evidence SHA256 hashes are checked before and after each run.
- Reports distinguish supported findings from unsupported or missing-artifact claims.
- Raw planner output is saved for auditability.

## Current Status

MVP is viable for a FIND EVIL submission package. The repository includes runnable demos, license, architecture documentation, benchmark result, accuracy report, and execution artifacts. Remaining Devpost work is to upload the demo video and paste the hosted video URL into the submission form.
