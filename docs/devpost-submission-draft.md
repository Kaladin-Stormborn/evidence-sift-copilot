# Devpost Submission Draft

## Project Name

Evidence SIFT Copilot

## Tagline

An evidence-backed Protocol SIFT-style DFIR copilot that plans investigations, runs allowlisted tools, and refuses unsupported forensic claims.

## Built With

- Python
- GPT-5.5 via local Codex CLI
- Protocol SIFT-style case folders
- DFIR-Metric benchmark
- JSONL audit logs
- Markdown reports

## What It Does

Evidence SIFT Copilot investigates incident-response case folders without letting the model invent evidence.

The model proposes a plan from an allowlist. The runner validates that plan, executes deterministic read-only tools, records every tool call, and writes an audit-ready report. The system keeps a claim ledger so each conclusion is marked as supported, unsupported, or needing more artifacts.

The demo includes two cases:

- A synthetic Protocol SIFT-style case that shows self-correction and refusal.
- A DFIR-Metric benchmark case where the system identifies the malicious obfuscated web-log source IP and matches the ground truth answer.

## Why It Matters

Most AI security demos fail at forensic discipline. They produce fluent reports, but the reader cannot always trace claims back to exact evidence.

Evidence SIFT Copilot is designed around the opposite posture: every finding must cite tool output, and unsupported claims must be downgraded.

## How It Works

1. Case folder provides evidence and case instructions.
2. GPT-5.5 planner chooses steps from an allowlisted tool set.
3. Plan validator rejects unsupported tools or missing claim guard.
4. Deterministic tools inspect logs/hashes/process snapshots.
5. Claim guard downgrades unsupported conclusions.
6. Reports, claim ledger, raw planner output, and audit logs are written to disk.

## Challenges

- Balancing autonomy with forensic safety.
- Preventing broad shell access while keeping the system useful.
- Making the demo small enough to run quickly but realistic enough to prove the judging criteria.
- Building a benchmark path that does not require giant forensic images.

## What We Learned

The best shape is not a generic AI SOC. It is a narrow Protocol SIFT copilot with strict evidence boundaries.

The planner can be agentic, but evidence must come from deterministic tools. This split is what makes the system auditable.

## Accomplishments

- Built a SIFT-style case workflow.
- Added GPT-5.5 planner through local Codex CLI.
- Added allowlisted tool validation.
- Added audit logs, claim ledger, and self-correction/refusal behavior.
- Solved a DFIR-Metric benchmark case correctly:
  - produced: `<xml>10.12.19.134</xml>`
  - ground truth: `<xml>10.12.19.134</xml>`

## What's Next

- Add more DFIR-Metric benchmark cases.
- Add support for real SIFT tools such as Plaso, Sleuth Kit, YARA, and Volatility.
- Export architecture diagram as an image.
- Add packaged demo data and scoring summaries for reviewers.

## GitHub Repo

https://github.com/Kaladin-Stormborn/evidence-sift-copilot

## Try It Out

```bash
git clone https://github.com/Kaladin-Stormborn/evidence-sift-copilot.git
cd evidence-sift-copilot
./run_synthetic.sh
./run_benchmark.sh
```
