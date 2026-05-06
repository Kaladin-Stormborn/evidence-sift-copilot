# Video Voiceover Script

Evidence SIFT Copilot is a Protocol SIFT-style incident response assistant built for one simple rule: no claim without evidence.

Most security agent demos look impressive because they write fluent reports. But in forensics, fluency is not enough. A practitioner needs to know exactly which tool produced each finding, which artifact supports it, and where the model stopped because the evidence was missing.

This project splits the work into two parts. GPT-5.5 chooses an investigation plan from a small allowlist. Then a deterministic runner validates that plan and executes only approved read-only tools. The model does not get arbitrary shell access through the demo runner.

Every run writes the raw planner output, a normalized plan, a command-level audit log, a claim ledger, and a Markdown report. The synthetic SIFT-style case shows the self-correction behavior. The agent finds suspicious login activity, web upload activity, process execution from temporary paths, and a known-bad payload hash. But it refuses to name a real-world threat actor, because the case does not contain threat intelligence. It also downgrades data exfiltration to needs artifact, because there are no packet captures, proxy logs, or endpoint telemetry proving exfiltration.

The benchmark case uses DFIR-Metric, a public benchmark for digital forensics and incident response tasks. The task is to identify the IP responsible for obfuscated malicious web requests. GPT-5.5 selects the plan: detect obfuscation, decode payloads, score source IPs, then run claim guard. The deterministic tools find fourteen suspicious requests from one IP, decode malicious payloads including JavaScript and PHP command execution strings, and select ten dot twelve dot nineteen dot one thirty four. The benchmark answer key matches: ten dot twelve dot nineteen dot one thirty four.

The important part is not that the answer is correct once. It is that the answer is auditable. The plan is saved as JSONL. The audit log includes command IDs, input paths, timestamps, decoded payloads, and rows. The claims file records the final answer and links it to the evidence-producing commands.

For FIND EVIL, this is the core argument. Evidence SIFT Copilot is agentic enough to plan and self-correct, deterministic enough to audit, and constrained enough to avoid hallucinated forensic conclusions. It is not trying to be a broad AI SOC. It is a focused forensic copilot that helps an analyst trust what the agent says, because every claim can be traced back to tool output.
