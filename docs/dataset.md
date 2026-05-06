# Dataset Documentation

## Included Cases

### Synthetic SIFT-Style Case

Path:

- `cases/synthetic-sift/evidence/sample-case/`

Files:

- `auth.log`: synthetic SSH authentication timeline.
- `web.log`: synthetic admin/upload web activity.
- `processes.txt`: synthetic process snapshot.
- `hashes.csv`: synthetic observed file hashes.
- `known_bad_hashes.csv`: synthetic known-bad hash reference.
- `answer_key.md`: expected investigation conclusions.

Purpose:

- Demonstrates multi-artifact correlation across auth, web, process, and hash evidence.
- Demonstrates claim downgrade behavior for unsupported actor attribution and exfiltration.

Provenance:

- Created for this FIND EVIL submission.
- No real users, systems, secrets, or production incident data.

### DFIR-Metric Web Obfuscation Case

Path:

- `cases/dfir-metric-web-obfuscation/evidence/dfir-metric-web-obfuscation/`

Files:

- `web.log`: benchmark web log evidence.
- `question.md`: benchmark task statement.
- `answer_key.md`: expected answer.

Source:

- `Neo111x/DFIR-Metric`
- Module II CTF-style web obfuscation challenge.
- Local benchmark answer: `<xml>10.12.19.134</xml>`.

License:

- The source dataset card identifies DFIR-Metric as Apache 2.0.

## Evidence Integrity

Each runner records a before/after SHA256 manifest for every evidence file:

- `analysis/chain-of-custody.jsonl`
- `analysis-agentic/chain-of-custody.jsonl`

The run halts if an evidence file changes during analysis. Outputs are written outside the evidence directory.

## Limitations

- The benchmark case is log-only.
- The synthetic case is useful for guardrails and self-correction, but it is not a substitute for broad SIFT coverage.
- Future work should add disk-image, memory, and pcap cases with documented public provenance.
