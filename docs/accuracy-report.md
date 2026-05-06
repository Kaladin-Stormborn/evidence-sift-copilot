# Accuracy Report

## Benchmark Result

Dataset:

- `Neo111x/DFIR-Metric`
- Module II CTF-style web obfuscation challenge
- Local case: `cases/dfir-metric-web-obfuscation/evidence/dfir-metric-web-obfuscation/`

Task:

- Identify the IP address responsible for obfuscated malicious web requests.

Ground truth:

- `<xml>10.12.19.134</xml>`

System output:

- `<xml>10.12.19.134</xml>`

Result:

- Correct.

## Claim-Level Accuracy

| Case | Claim Type | Expected | System Status | Result |
| --- | --- | --- | --- | --- |
| DFIR-Metric web obfuscation | Responsible source IP | `10.12.19.134` | supported | true positive |
| Synthetic SIFT-style | SSH brute force/success from `185.199.110.153` | supported | supported | true positive |
| Synthetic SIFT-style | Admin upload activity from same IP | supported | supported | true positive |
| Synthetic SIFT-style | Suspicious `/tmp` execution and known-bad hash | supported | supported | true positive |
| Synthetic SIFT-style | Named real-world actor attribution | unsupported | unsupported | true negative |
| Synthetic SIFT-style | Data exfiltration occurred | needs additional artifact | needs_artifact | correctly withheld |

## False Positives

- DFIR-Metric: no other IPs were selected as responsible.
- Synthetic: the system did not promote actor attribution or exfiltration to supported findings.

## Missed Artifacts

- DFIR-Metric is log-only. There are no packet captures, endpoint artifacts, memory captures, or server-side files to inspect.
- Synthetic case includes auth, web, process, and hash evidence, but no pcap, proxy logs, endpoint telemetry, or threat intelligence.

## Hallucinated Claims

The synthetic case intentionally contains tempting but unsupported conclusions:

- "The intrusion can be attributed to a named real-world threat actor."
- "Data exfiltration occurred."

The claim guard downgrades these in `claims.jsonl`, and the agentic runner now writes a separate model critic pass to `self-correction.md` plus raw output in `claim-review.raw.txt`.

## Evidence Integrity And Spoliation Protection

Each run computes SHA256 hashes for every evidence file before and after analysis. The manifest is written to:

- `analysis/chain-of-custody.jsonl`
- `analysis-agentic/chain-of-custody.jsonl`

If any evidence file changes during analysis, the runner raises an error and does not silently continue. Evidence directories are read by deterministic tools; generated outputs are written to analysis directories.

## What Happens If The Model Ignores Restrictions

The planner output is validated before execution:

- unsupported tools such as `shell` or `rm` are rejected
- synthetic plans must include `claim_guard`
- benchmark plans must end with `claim_guard`

The guardrail behavior is covered by:

- `tests/test_guardrails.py`

## Token Usage

The local Codex CLI runner does not expose token counts to this Python harness. Audit rows therefore include:

- `token_usage.available = false`
- `token_usage.reason = local Codex CLI did not expose token counts to this runner`

Planner raw files include model and wall-clock runtime metadata.

## Limitations

This is still a compact submission slice. It proves the evidence-backed architecture against one public benchmark and one synthetic multi-artifact case. It does not yet prove broad SIFT coverage over full disk images, memory captures, or packet captures.
