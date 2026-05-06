# FIND EVIL Synthetic SIFT-Compatible Case

## Case Overview

| Field | Value |
| --- | --- |
| Client | Synthetic Lab |
| Scenario | Linux web host intrusion triage |
| Role | DFIR orchestrator |
| Evidence Mode | Strict read-only |

## Evidence Files

| File | Notes |
| --- | --- |
| `./evidence/sample-case/auth.log` | SSH authentication events |
| `./evidence/sample-case/web.log` | Web access events |
| `./evidence/sample-case/processes.txt` | Process snapshot |
| `./evidence/sample-case/hashes.csv` | File hash inventory |
| `./evidence/sample-case/known_bad_hashes.csv` | Synthetic known-bad hash labels |
| `./evidence/sample-case/answer_key.md` | Ground truth for scoring |

Evidence files are read-only inputs for the investigation. Do not modify files under `./evidence/`.

## Output Routing

Write generated artifacts only to:

- `./analysis/`
- `./reports/`
- `./exports/`

## Investigation Rules

- Ground every claim in deterministic tool output.
- Cite command IDs and source rows for each supported finding.
- Mark unsupported attribution as unsupported.
- Mark data exfiltration as `needs_artifact` unless evidence exists.
- Preserve UTC timestamps.

## Demo Command

From this case directory:

```bash
python3 ../prototype/case_investigator.py --case-dir ./evidence/sample-case --out-dir ./analysis
```

Expected outputs:

- `./analysis/report.md`
- `./analysis/claims.jsonl`
- `./analysis/audit-log.jsonl`
- `./analysis/plan.jsonl`
- `./analysis/self-correction.md`
- `./analysis-agentic/report.md`
- `./analysis-agentic/claims.jsonl`
- `./analysis-agentic/audit-log.jsonl`
- `./analysis-agentic/plan.jsonl`
- `./analysis-agentic/self-correction.md`
- `./analysis-agentic/agent-planner.raw.txt`
