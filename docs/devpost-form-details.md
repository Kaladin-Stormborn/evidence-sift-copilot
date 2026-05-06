# Devpost Form Details

## Project Name

Evidence SIFT Copilot

## Tagline

An evidence-backed Protocol SIFT-style DFIR copilot that plans investigations, runs allowlisted tools, and refuses unsupported forensic claims.

## Repository

https://github.com/Kaladin-Stormborn/evidence-sift-copilot

## Demo Video

Paste uploaded video URL here.

## Built With

Python, GPT-5.5 via local Codex CLI, Protocol SIFT-style case folders, DFIR-Metric, JSONL audit logs, Markdown reports.

## Short Description

Evidence SIFT Copilot is an autonomous incident-response assistant designed around forensic discipline. The model chooses a plan from an allowlist, the runner validates it, deterministic tools produce the evidence, and the report records every claim with audit trail references.

## Long Description

Most AI security demos produce fluent incident reports, but the evidence trail is often weak. Evidence SIFT Copilot takes the opposite approach: no claim without deterministic tool output.

The system starts from a Protocol SIFT-style case folder. GPT-5.5, through the local Codex CLI, selects investigation steps from an explicit allowlist. A validator rejects unsupported tools or missing claim-guard steps. Deterministic Python tools inspect logs, hashes, and process snapshots, then write JSONL audit logs, a claim ledger, raw planner output, and a Markdown report.

The demo includes two cases:

1. A synthetic SIFT-style case showing self-correction: the agent finds suspicious login and payload evidence but refuses unsupported actor attribution and downgrades exfiltration to `needs_artifact`.
2. A DFIR-Metric benchmark case where the system identifies the responsible IP for obfuscated malicious web requests. It outputs `<xml>10.12.19.134</xml>`, matching the benchmark ground truth.

## Challenges

- Keeping the agent autonomous without giving it arbitrary shell access.
- Preventing hallucinated forensic conclusions.
- Making every claim traceable to tool output.
- Finding a benchmark that is credible but lightweight enough for reviewers to run.

## Accomplishments

- Built a Protocol SIFT-style case workflow.
- Added GPT-5.5 planner integration.
- Added allowlisted plan validation.
- Added deterministic tool execution.
- Added raw planner output, audit logs, claim ledger, self-correction log, and evidence-backed reports.
- Solved a DFIR-Metric benchmark case correctly.

## What We Learned

The safest architecture is a split between agentic planning and deterministic execution. The model can decide what to inspect, but tools must generate the evidence and the claim guard must downgrade anything unsupported.

## What's Next

- Add more DFIR-Metric benchmark cases.
- Add direct SIFT tool adapters for Plaso, Sleuth Kit, YARA, and Volatility.
- Export richer HTML/PDF reports.
- Package case templates for broader Protocol SIFT use.

## Try It Out

```bash
git clone https://github.com/Kaladin-Stormborn/evidence-sift-copilot.git
cd evidence-sift-copilot
./run_synthetic.sh
./run_benchmark.sh
```

## License

MIT
