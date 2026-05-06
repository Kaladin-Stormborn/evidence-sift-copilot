# Demo Script

Target length: under 5 minutes.

## 1. Open

Show the objective:

- Evidence SIFT Copilot is not a generic AI SOC.
- It is a Protocol SIFT-style copilot that refuses unsupported claims.

## 2. Show Case Folder

Show:

```bash
find cases -maxdepth 3 -type f | sort | sed -n '1,80p'
```

Point out:

- `CLAUDE.md`
- `evidence/`
- `analysis-agentic/`

## 3. Run Synthetic Case

```bash
./run_synthetic.sh
```

Show:

- `analysis-agentic/plan.jsonl`
- `analysis-agentic/audit-log.jsonl`
- `analysis-agentic/report.md`
- `analysis-agentic/self-correction.md`

Narration:

- GPT-5.5 chose the plan.
- Runner validated the plan.
- Tools produced evidence.
- Claim guard downgraded attribution and exfiltration.

## 4. Run Benchmark Case

```bash
./run_benchmark.sh
```

Show:

- produced answer: `<xml>10.12.19.134</xml>`
- answer key: `<xml>10.12.19.134</xml>`
- decoded payload evidence in `analysis-agentic/audit-log.jsonl`

## 5. Close

Judging story:

- Agentic enough to plan and self-correct.
- Deterministic enough to audit.
- Guarded enough to avoid hallucinated forensic conclusions.
