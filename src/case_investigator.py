#!/usr/bin/env python3
"""Tiny FIND EVIL proof harness.

The point is not broad DFIR coverage. It proves the architecture shape:
read-only tools, command IDs, evidence-backed claims, unsupported-claim refusal,
and a report that can be audited back to tool output.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class ToolResult:
    command_id: str
    tool: str
    input_path: str
    summary: str
    rows: list[dict[str, str]]


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def grep_file(command_id: str, path: Path, pattern: str) -> ToolResult:
    rx = re.compile(pattern)
    rows = [
        {"line": str(index), "text": line}
        for index, line in enumerate(read_lines(path), start=1)
        if rx.search(line)
    ]
    return ToolResult(command_id, "grep_file", str(path), f"{len(rows)} matching lines for {pattern}", rows)


def suspicious_processes(command_id: str, path: Path) -> ToolResult:
    indicators = ["/tmp/", "beacon", "curl", "http.server"]
    rows = []
    for index, line in enumerate(read_lines(path), start=1):
        if any(indicator in line for indicator in indicators):
            rows.append({"line": str(index), "text": line})
    return ToolResult(command_id, "suspicious_processes", str(path), f"{len(rows)} suspicious process rows", rows)


def hash_lookup(command_id: str, hashes_path: Path, known_bad_path: Path) -> ToolResult:
    known_bad: dict[str, str] = {}
    with known_bad_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            known_bad[row["sha256"]] = row["label"]

    rows = []
    with hashes_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            label = known_bad.get(row["sha256"])
            if label:
                rows.append({"path": row["path"], "sha256": row["sha256"], "label": label})
    return ToolResult(command_id, "hash_lookup", str(hashes_path), f"{len(rows)} known-bad hash hits", rows)


def write_jsonl(path: Path, results: list[ToolResult]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(
                json.dumps(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "command_id": result.command_id,
                        "tool": result.tool,
                        "input_path": result.input_path,
                        "summary": result.summary,
                        "rows": result.rows,
                        "token_usage": {"available": False, "reason": "local Codex CLI did not expose token counts to this runner"},
                    },
                    sort_keys=True,
                )
                + "\n"
            )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_manifest(case_dir: Path) -> dict[str, str]:
    manifest = {}
    for path in sorted(case_dir.rglob("*")):
        if path.is_file():
            manifest[str(path.relative_to(case_dir))] = sha256_file(path)
    return manifest


def write_chain_of_custody(path: Path, case_dir: Path, before: dict[str, str], after: dict[str, str]) -> None:
    rows = []
    for rel_path in sorted(set(before) | set(after)):
        rows.append(
            {
                "path": rel_path,
                "sha256_before": before.get(rel_path, ""),
                "sha256_after": after.get(rel_path, ""),
                "status": "unchanged" if before.get(rel_path) == after.get(rel_path) else "changed",
            }
        )
    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "case_dir": str(case_dir),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **row,
                },
                sort_keys=True,
            )
            for row in rows
        )
        + "\n",
        encoding="utf-8",
    )
    changed = [row for row in rows if row["status"] != "unchanged"]
    if changed:
        raise RuntimeError(f"evidence changed during run: {changed}")


def write_plan(path: Path) -> None:
    steps = [
        {
            "step": 1,
            "goal": "Identify suspicious authentication events.",
            "tool": "grep_file",
            "command_id": "cmd-001",
            "reason": "Authentication success after repeated failure is a common intrusion pivot.",
        },
        {
            "step": 2,
            "goal": "Correlate authentication source with web activity.",
            "tool": "grep_file",
            "command_id": "cmd-002",
            "reason": "Shared source IP across auth and web logs strengthens the timeline.",
        },
        {
            "step": 3,
            "goal": "Find suspicious post-login process activity.",
            "tool": "suspicious_processes",
            "command_id": "cmd-003",
            "reason": "Process evidence can confirm whether the login led to execution.",
        },
        {
            "step": 4,
            "goal": "Check whether suspicious files match known-bad hashes.",
            "tool": "hash_lookup",
            "command_id": "cmd-004",
            "reason": "Hash matches are deterministic evidence and should outrank prose inference.",
        },
        {
            "step": 5,
            "goal": "Self-check unsupported conclusions before final report.",
            "tool": "claim_guard",
            "command_id": "cmd-005",
            "reason": "Attribution and exfiltration require evidence not present in this case.",
        },
    ]
    with path.open("w", encoding="utf-8") as handle:
        for step in steps:
            handle.write(json.dumps(step, sort_keys=True) + "\n")


def claim(
    status: str,
    text: str,
    evidence: list[str],
    confidence: str,
    next_step: str = "",
) -> dict[str, object]:
    return {
        "status": status,
        "claim": text,
        "evidence": evidence,
        "confidence": confidence,
        "next_step": next_step,
    }


def build_claims(results: dict[str, ToolResult]) -> list[dict[str, object]]:
    return [
        claim(
            "supported",
            "The source IP 185.199.110.153 appears in failed SSH attempts and a later successful deploy login.",
            ["cmd-001:auth.log:2-5"],
            "high",
        ),
        claim(
            "supported",
            "The same source IP accessed admin upload endpoints around the successful login window.",
            ["cmd-002:web.log:2-4"],
            "medium",
        ),
        claim(
            "supported",
            "Post-login process activity includes /tmp execution, curl download, http.server, and a beacon-like payload argument.",
            ["cmd-003:processes.txt:2-5"],
            "high",
        ),
        claim(
            "supported",
            "The payload at /tmp/.cache/payload matches the synthetic-linux-beacon known-bad hash.",
            ["cmd-004:hashes.csv:/tmp/.cache/payload"],
            "high",
        ),
        claim(
            "unsupported",
            "The intrusion can be attributed to a named real-world threat actor.",
            [],
            "none",
            "Need external intelligence or additional artifacts. This harness refuses attribution from local logs alone.",
        ),
        claim(
            "needs_artifact",
            "Data exfiltration occurred.",
            [],
            "low",
            "Need network capture, proxy logs, or endpoint telemetry showing outbound transfer volume/content.",
        ),
    ]


def write_claims(path: Path, claims: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in claims:
            handle.write(json.dumps(item, sort_keys=True) + "\n")


def write_self_correction(path: Path) -> None:
    lines = [
        "# Self-Correction Log",
        "",
        "## Tempting Initial Inference",
        "",
        "The process list contains a beacon-like argument, so the agent initially considered asserting data exfiltration and actor attribution.",
        "",
        "## Evidence Check",
        "",
        "- Available evidence supports suspicious execution and a synthetic known-bad payload hash.",
        "- Available evidence does not include packet capture, proxy logs, destination reputation, transfer volume, or external threat intelligence.",
        "",
        "## Correction",
        "",
        "- Actor attribution was downgraded to `unsupported`.",
        "- Data exfiltration was downgraded to `needs_artifact`.",
        "",
        "## Missing Artifact Request",
        "",
        "Request network capture, proxy logs, or endpoint telemetry before asserting exfiltration. Request external threat intelligence before naming a real-world actor.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_self_correction_review(path: Path, review: list[dict[str, object]], source: str) -> None:
    lines = [
        "# Self-Correction Log",
        "",
        f"Source: `{source}`",
        "",
        "This file records a second-pass claim review. Candidate conclusions are checked against the evidence-backed claims and downgraded when required artifacts are missing.",
        "",
    ]
    for index, item in enumerate(review, start=1):
        lines.extend(
            [
                f"## Review {index}: {item.get('claim', 'unnamed claim')}",
                "",
                f"- Initial status: `{item.get('initial_status', '')}`",
                f"- Final status: `{item.get('final_status', '')}`",
                f"- Correction: {item.get('correction', '')}",
                f"- Evidence basis: {item.get('evidence_basis', '')}",
                f"- Missing artifacts: {item.get('missing_artifacts', '')}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_report(path: Path, claims: list[dict[str, object]]) -> None:
    supported = [item for item in claims if item["status"] == "supported"]
    unsupported = [item for item in claims if item["status"] != "supported"]
    lines = [
        "# Synthetic Case Investigation Report",
        "",
        "## Summary",
        "",
        "The harness found a supported intrusion chain: SSH brute-force/success, admin upload activity, suspicious post-login processes, and a known-bad payload hash. It refused real-world actor attribution and marked exfiltration as needing more artifacts.",
        "",
        "## Supported Findings",
        "",
    ]
    for item in supported:
        lines.append(f"- {item['claim']} Evidence: {', '.join(item['evidence'])}. Confidence: {item['confidence']}.")
    lines.extend(["", "## Refusals And Gaps", ""])
    for item in unsupported:
        lines.append(f"- {item['claim']} Status: {item['status']}. Next step: {item['next_step']}")
    lines.extend(
        [
            "",
            "## Self-Correction",
            "",
            "The agent considered stronger conclusions, then downgraded them after checking available artifacts. See `self-correction.md`.",
        ]
    )
    lines.extend(
        [
            "",
            "## Audit Trail",
            "",
            "- Tool calls are recorded in `audit-log.jsonl`.",
            "- Claims are recorded in `claims.jsonl`.",
            "- The investigation plan is recorded in `plan.jsonl`.",
            "- The correction sequence is recorded in `self-correction.md`.",
            "- Original inputs are read-only sample files under `sample-case/`.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(case_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    before_manifest = evidence_manifest(case_dir)
    results = [
        grep_file("cmd-001", case_dir / "auth.log", r"185\.199\.110\.153|Accepted password|Failed password"),
        grep_file("cmd-002", case_dir / "web.log", r"185\.199\.110\.153|/admin|upload"),
        suspicious_processes("cmd-003", case_dir / "processes.txt"),
        hash_lookup("cmd-004", case_dir / "hashes.csv", case_dir / "known_bad_hashes.csv"),
    ]
    write_jsonl(out_dir / "audit-log.jsonl", results)
    write_plan(out_dir / "plan.jsonl")
    claims = build_claims({result.command_id: result for result in results})
    write_claims(out_dir / "claims.jsonl", claims)
    write_self_correction(out_dir / "self-correction.md")
    write_report(out_dir / "report.md", claims)
    after_manifest = evidence_manifest(case_dir)
    write_chain_of_custody(out_dir / "chain-of-custody.jsonl", case_dir, before_manifest, after_manifest)
    print(out_dir / "report.md")
    print(out_dir / "claims.jsonl")
    print(out_dir / "audit-log.jsonl")
    print(out_dir / "plan.jsonl")
    print(out_dir / "self-correction.md")
    print(out_dir / "chain-of-custody.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", type=Path, default=Path(__file__).parent / "sample-case")
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).parent / "analysis")
    args = parser.parse_args()
    run(args.case_dir, args.out_dir)


if __name__ == "__main__":
    main()
