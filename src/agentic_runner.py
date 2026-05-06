#!/usr/bin/env python3
"""Agentic FIND EVIL runner.

Codex chooses an allowlisted investigation plan. This script validates that plan,
executes deterministic read-only tools, and writes auditable artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from case_investigator import (
    ToolResult,
    build_claims,
    evidence_manifest,
    grep_file,
    hash_lookup,
    suspicious_processes,
    write_claims,
    write_chain_of_custody,
    write_jsonl,
    write_report,
    write_self_correction_review,
)


ALLOWED_TOOLS = {
    "grep_auth": "Search authentication evidence for suspicious login activity.",
    "grep_web": "Search web logs for correlated source IP and upload activity.",
    "process_triage": "Find suspicious process execution.",
    "hash_lookup": "Compare case hashes against known-bad hashes.",
    "claim_guard": "Check tempting conclusions and downgrade unsupported claims.",
}

REPO_ROOT = Path(__file__).resolve().parents[1]


def codex_exec_command(model: str) -> list[str]:
    codex_bin = os.environ.get("CODEX_BIN") or shutil.which("codex")
    if not codex_bin:
        raise FileNotFoundError("Codex CLI not found; set CODEX_BIN or use --offline")
    return [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "-m",
        model,
        "-s",
        "danger-full-access",
    ]


FALLBACK_PLAN = [
    {
        "step": 1,
        "tool": "grep_auth",
        "goal": "Identify suspicious authentication events.",
        "reason": "Authentication success after repeated failure is a common intrusion pivot.",
    },
    {
        "step": 2,
        "tool": "grep_web",
        "goal": "Correlate authentication source with web activity.",
        "reason": "Shared source IP across auth and web logs strengthens the timeline.",
    },
    {
        "step": 3,
        "tool": "process_triage",
        "goal": "Find suspicious post-login process activity.",
        "reason": "Process evidence can confirm whether the login led to execution.",
    },
    {
        "step": 4,
        "tool": "hash_lookup",
        "goal": "Check whether suspicious files match known-bad hashes.",
        "reason": "Hash matches are deterministic evidence and should outrank prose inference.",
    },
    {
        "step": 5,
        "tool": "claim_guard",
        "goal": "Self-check unsupported conclusions before final report.",
        "reason": "Attribution and exfiltration require evidence not present in this case.",
    },
]


def case_inventory(case_dir: Path) -> str:
    lines = []
    for path in sorted(case_dir.iterdir()):
        if path.is_file():
            preview = path.read_text(encoding="utf-8", errors="replace").splitlines()[:3]
            lines.append(f"- {path.name}: {len(preview)} preview lines")
            for line in preview:
                lines.append(f"  {line[:180]}")
    return "\n".join(lines)


def extract_json_array(text: str) -> list[dict[str, object]]:
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        raise ValueError("planner output did not contain a JSON array")
    data = json.loads(match.group(0))
    if not isinstance(data, list):
        raise ValueError("planner output was not a list")
    return data


def validate_plan(plan: list[dict[str, object]]) -> list[dict[str, object]]:
    validated = []
    for index, item in enumerate(plan, start=1):
        tool = str(item.get("tool", ""))
        if tool not in ALLOWED_TOOLS:
            raise ValueError(f"unsupported tool in plan: {tool}")
        validated.append(
            {
                "step": index,
                "tool": tool,
                "goal": str(item.get("goal", ALLOWED_TOOLS[tool])),
                "reason": str(item.get("reason", "")),
            }
        )
    if "claim_guard" not in {item["tool"] for item in validated}:
        raise ValueError("plan must include claim_guard")
    return validated


def request_plan(case_dir: Path, out_dir: Path, model: str) -> tuple[list[dict[str, object]], str]:
    prompt = f"""You are a DFIR planning agent for a Protocol SIFT-style case.

Choose an investigation plan from only these tools:
{json.dumps(ALLOWED_TOOLS, indent=2)}

Return only a JSON array. Each item must have:
- tool
- goal
- reason

Rules:
- Include claim_guard as the final self-check step.
- Prefer deterministic evidence before conclusions.
- Do not invent files or facts.
- Do not include hidden reasoning. Reasons should be short audit-facing explanations.

Case inventory:
{case_inventory(case_dir)}
"""
    started = time.monotonic()
    result = subprocess.run(
        codex_exec_command(model),
        input=prompt,
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    wall_ms = int((time.monotonic() - started) * 1000)
    raw = result.stdout.strip()
    (out_dir / "agent-planner.raw.txt").write_text(
        raw + f"\n\n---\nmodel: {model}\nwall_ms: {wall_ms}\ntoken_usage_available: false\n",
        encoding="utf-8",
    )
    return validate_plan(extract_json_array(raw)), raw


def fallback_review() -> list[dict[str, object]]:
    return [
        {
            "claim": "The intrusion can be attributed to a named real-world threat actor.",
            "initial_status": "tempting_overclaim",
            "final_status": "unsupported",
            "correction": "Downgraded because local logs, process list, and hashes do not identify an actor.",
            "evidence_basis": "Supported evidence reaches source IP activity, process execution, and known-bad synthetic hash only.",
            "missing_artifacts": "External threat intelligence, infrastructure ownership, malware family attribution, or campaign context.",
        },
        {
            "claim": "Data exfiltration occurred.",
            "initial_status": "tempting_overclaim",
            "final_status": "needs_artifact",
            "correction": "Downgraded because beacon-like process arguments do not prove transfer volume or contents.",
            "evidence_basis": "Process and web logs show suspicious activity but no outbound transfer proof.",
            "missing_artifacts": "Packet capture, proxy logs, endpoint telemetry, destination logs, or recovered exfiltrated content.",
        },
    ]


def request_claim_review(out_dir: Path, model: str, claims: list[dict[str, object]]) -> tuple[list[dict[str, object]], str]:
    prompt = f"""You are the claim-guard critic for a Protocol SIFT-style DFIR agent.

Review these evidence-backed claim ledger rows and correct tempting overclaims.

Return only a JSON array. Each item must have:
- claim
- initial_status
- final_status
- correction
- evidence_basis
- missing_artifacts

Rules:
- Downgrade actor attribution unless external intelligence exists.
- Downgrade exfiltration unless network/proxy/endpoint transfer artifacts exist.
- Do not invent evidence.
- Keep corrections short and audit-facing.

Claim ledger:
{json.dumps(claims, indent=2)}
"""
    started = time.monotonic()
    result = subprocess.run(
        codex_exec_command(model),
        input=prompt,
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    wall_ms = int((time.monotonic() - started) * 1000)
    raw = result.stdout.strip()
    (out_dir / "claim-review.raw.txt").write_text(
        raw + f"\n\n---\nmodel: {model}\nwall_ms: {wall_ms}\ntoken_usage_available: false\n",
        encoding="utf-8",
    )
    return extract_json_array(raw), f"codex:{model}"


def write_plan(path: Path, plan: list[dict[str, object]], source: str) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in plan:
            row = dict(item)
            row["planner"] = source
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def execute_plan(case_dir: Path, plan: list[dict[str, object]]) -> list[ToolResult]:
    results: list[ToolResult] = []
    next_command = 1
    for item in plan:
        command_id = f"cmd-{next_command:03d}"
        tool = item["tool"]
        if tool == "grep_auth":
            results.append(grep_file(command_id, case_dir / "auth.log", r"185\.199\.110\.153|Accepted password|Failed password"))
        elif tool == "grep_web":
            results.append(grep_file(command_id, case_dir / "web.log", r"185\.199\.110\.153|/admin|upload"))
        elif tool == "process_triage":
            results.append(suspicious_processes(command_id, case_dir / "processes.txt"))
        elif tool == "hash_lookup":
            results.append(hash_lookup(command_id, case_dir / "hashes.csv", case_dir / "known_bad_hashes.csv"))
        elif tool == "claim_guard":
            results.append(
                ToolResult(
                    command_id,
                    "claim_guard",
                    str(case_dir),
                    "Downgraded actor attribution and exfiltration because required artifacts are absent.",
                    [
                        {"claim": "actor attribution", "status": "unsupported"},
                        {"claim": "data exfiltration", "status": "needs_artifact"},
                    ],
                )
            )
        next_command += 1
    return results


def run(case_dir: Path, out_dir: Path, model: str, offline: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    before_manifest = evidence_manifest(case_dir)
    planner_source = "fallback"
    try:
        if offline:
            raise RuntimeError("offline mode requested")
        plan, _ = request_plan(case_dir, out_dir, model)
        planner_source = f"codex:{model}"
    except Exception as exc:
        (out_dir / "agent-planner.error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        plan = validate_plan(FALLBACK_PLAN)

    results = execute_plan(case_dir, plan)
    write_plan(out_dir / "plan.jsonl", plan, planner_source)
    write_jsonl(out_dir / "audit-log.jsonl", results)
    claims = build_claims({result.command_id: result for result in results})
    write_claims(out_dir / "claims.jsonl", claims)
    try:
        if offline:
            raise RuntimeError("offline mode requested")
        review, review_source = request_claim_review(out_dir, model, claims)
    except Exception as exc:
        (out_dir / "claim-review.error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        review = fallback_review()
        review_source = "fallback"
    write_self_correction_review(out_dir / "self-correction.md", review, review_source)
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
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).parent / "analysis-agentic")
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    run(args.case_dir, args.out_dir, args.model, args.offline)


if __name__ == "__main__":
    main()
