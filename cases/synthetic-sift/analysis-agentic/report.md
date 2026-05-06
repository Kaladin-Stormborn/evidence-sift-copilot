# Synthetic Case Investigation Report

## Summary

The harness found a supported intrusion chain: SSH brute-force/success, admin upload activity, suspicious post-login processes, and a known-bad payload hash. It refused real-world actor attribution and marked exfiltration as needing more artifacts.

## Supported Findings

- The source IP 185.199.110.153 appears in failed SSH attempts and a later successful deploy login. Evidence: cmd-001:auth.log:2-5. Confidence: high.
- The same source IP accessed admin upload endpoints around the successful login window. Evidence: cmd-002:web.log:2-4. Confidence: medium.
- Post-login process activity includes /tmp execution, curl download, http.server, and a beacon-like payload argument. Evidence: cmd-003:processes.txt:2-5. Confidence: high.
- The payload at /tmp/.cache/payload matches the synthetic-linux-beacon known-bad hash. Evidence: cmd-004:hashes.csv:/tmp/.cache/payload. Confidence: high.

## Refusals And Gaps

- The intrusion can be attributed to a named real-world threat actor. Status: unsupported. Next step: Need external intelligence or additional artifacts. This harness refuses attribution from local logs alone.
- Data exfiltration occurred. Status: needs_artifact. Next step: Need network capture, proxy logs, or endpoint telemetry showing outbound transfer volume/content.

## Self-Correction

The agent considered stronger conclusions, then downgraded them after checking available artifacts. See `self-correction.md`.

## Audit Trail

- Tool calls are recorded in `audit-log.jsonl`.
- Claims are recorded in `claims.jsonl`.
- The investigation plan is recorded in `plan.jsonl`.
- The correction sequence is recorded in `self-correction.md`.
- Original inputs are read-only sample files under `sample-case/`.
