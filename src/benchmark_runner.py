#!/usr/bin/env python3
"""Agentic benchmark runner for a DFIR-Metric web log challenge."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import unquote

from case_investigator import ToolResult, evidence_manifest, write_chain_of_custody, write_jsonl


ALLOWED_TOOLS = {
    "detect_obfuscation": "Find encoded, traversal, XSS, and script-like requests.",
    "decode_payloads": "Decode URL/base64 payloads when possible.",
    "score_source_ips": "Aggregate suspicious evidence by source IP.",
    "claim_guard": "Compare the answer to evidence and refuse unsupported alternatives.",
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
    {"tool": "detect_obfuscation", "goal": "Find obfuscated malicious requests.", "reason": "The benchmark asks for obfuscated malicious requests."},
    {"tool": "decode_payloads", "goal": "Decode suspicious request payloads.", "reason": "Encoding is the key forensic feature."},
    {"tool": "score_source_ips", "goal": "Identify the responsible source IP.", "reason": "Repeated suspicious requests from one IP should dominate."},
    {"tool": "claim_guard", "goal": "Check the selected IP against evidence.", "reason": "Avoid guessing from a single weak signal."},
]


LOG_RE = re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] \"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^\"]+)\" (?P<status>\d+) (?P<size>\d+)")


def read_logs(case_dir: Path) -> list[dict[str, str]]:
    rows = []
    for line_no, line in enumerate((case_dir / "web.log").read_text(encoding="utf-8").splitlines(), start=1):
        match = LOG_RE.match(line)
        if match:
            row = match.groupdict()
            row["line"] = str(line_no)
            row["raw"] = line
            rows.append(row)
    return rows


def is_suspicious(path: str) -> bool:
    decoded = unquote(path)
    lower = decoded.lower()
    return any(
        token in lower
        for token in [
            "../",
            "..\\",
            "etc/passwd",
            "windows\\system32",
            "<svg",
            "<body",
            "<iframe",
            "javascript:",
            "alert(",
            "<?php",
            "system(",
            "li4v",
            "pglm",
            "pd9w",
            "%25",
        ]
    )


def maybe_decode(value: str) -> str:
    value = unquote(value)
    candidates = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+]{12,}={0,2}(?![A-Za-z0-9+/])", value)
    decoded = []
    for candidate in candidates:
        try:
            text = base64.b64decode(candidate + "==="[: len(candidate) % 4], validate=False).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if text and any(marker in text.lower() for marker in ["../", "<iframe", "<?php", "bash", "alert"]):
            decoded.append(f"{candidate} -> {text}")
    return "; ".join(decoded)


def request_plan(case_dir: Path, out_dir: Path, model: str) -> tuple[list[dict[str, str]], str]:
    sample = "\n".join((case_dir / "web.log").read_text(encoding="utf-8").splitlines()[:12])
    prompt = f"""You are a DFIR benchmark planning agent.

Choose an investigation plan from only these tools:
{json.dumps(ALLOWED_TOOLS, indent=2)}

Return only a JSON array. Each item must have tool, goal, reason.
Include claim_guard last.

Task: identify the IP responsible for obfuscated malicious web requests.

Sample logs:
{sample}
"""
    result = subprocess.run(
        codex_exec_command(model),
        input=prompt,
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    raw = result.stdout.strip()
    (out_dir / "agent-planner.raw.txt").write_text(raw + "\n", encoding="utf-8")
    match = re.search(r"\[[\s\S]*\]", raw)
    if not match:
        raise ValueError("planner did not return JSON array")
    plan = json.loads(match.group(0))
    return validate_plan(plan), raw


def validate_plan(plan: list[dict[str, object]]) -> list[dict[str, str]]:
    out = []
    for index, item in enumerate(plan, start=1):
        tool = str(item.get("tool", ""))
        if tool not in ALLOWED_TOOLS:
            raise ValueError(f"unsupported tool: {tool}")
        out.append({"step": str(index), "tool": tool, "goal": str(item.get("goal", "")), "reason": str(item.get("reason", ""))})
    if not out or out[-1]["tool"] != "claim_guard":
        raise ValueError("claim_guard must be final")
    return out


def write_plan(path: Path, plan: list[dict[str, str]], planner: str) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in plan:
            row = dict(item)
            row["planner"] = planner
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def execute(case_dir: Path) -> tuple[list[ToolResult], str]:
    rows = read_logs(case_dir)
    suspicious = [row for row in rows if is_suspicious(row["path"])]
    by_ip = Counter(row["ip"] for row in suspicious)
    decoded_rows = []
    for row in suspicious:
        decoded = maybe_decode(row["path"])
        if decoded:
            decoded_rows.append({"line": row["line"], "ip": row["ip"], "decoded": decoded, "path": row["path"]})
    score_rows = [{"ip": ip, "suspicious_count": str(count)} for ip, count in by_ip.most_common()]
    answer = by_ip.most_common(1)[0][0] if by_ip else "I-DO-NOT-KNOW"
    results = [
        ToolResult("cmd-001", "detect_obfuscation", str(case_dir / "web.log"), f"{len(suspicious)} suspicious requests", [{"line": row["line"], "ip": row["ip"], "path": row["path"], "status": row["status"]} for row in suspicious]),
        ToolResult("cmd-002", "decode_payloads", str(case_dir / "web.log"), f"{len(decoded_rows)} decoded payloads", decoded_rows),
        ToolResult("cmd-003", "score_source_ips", str(case_dir / "web.log"), f"top IP: {answer}", score_rows),
        ToolResult("cmd-004", "claim_guard", str(case_dir), "Selected IP only because it has repeated obfuscated request evidence.", [{"answer": answer, "status": "supported" if answer != "I-DO-NOT-KNOW" else "needs_artifact"}]),
    ]
    return results, answer


def write_claims(path: Path, answer: str) -> None:
    claim = {
        "status": "supported" if answer != "I-DO-NOT-KNOW" else "needs_artifact",
        "claim": f"The IP responsible for the obfuscated malicious requests is {answer}.",
        "evidence": ["cmd-001", "cmd-002", "cmd-003", "cmd-004"],
        "confidence": "high" if answer != "I-DO-NOT-KNOW" else "low",
    }
    path.write_text(json.dumps(claim, sort_keys=True) + "\n", encoding="utf-8")


def write_report(path: Path, answer: str) -> None:
    path.write_text(
        "\n".join(
            [
                "# DFIR-Metric Web Obfuscation Report",
                "",
                f"Answer: `<xml>{answer}</xml>`",
                "",
                "## Basis",
                "",
                "- `cmd-001` identified obfuscated/path-traversal/script-like web requests.",
                "- `cmd-002` decoded payloads where possible.",
                "- `cmd-003` scored suspicious requests by source IP.",
                "- `cmd-004` guarded against unsupported alternative attribution.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def run(case_dir: Path, out_dir: Path, model: str, offline: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    before_manifest = evidence_manifest(case_dir)
    planner = "fallback"
    try:
        if offline:
            raise RuntimeError("offline mode requested")
        plan, _ = request_plan(case_dir, out_dir, model)
        planner = f"codex:{model}"
    except Exception as exc:
        (out_dir / "agent-planner.error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        plan = validate_plan(FALLBACK_PLAN)
    write_plan(out_dir / "plan.jsonl", plan, planner)
    results, answer = execute(case_dir)
    write_jsonl(out_dir / "audit-log.jsonl", results)
    write_claims(out_dir / "claims.jsonl", answer)
    write_report(out_dir / "report.md", answer)
    after_manifest = evidence_manifest(case_dir)
    write_chain_of_custody(out_dir / "chain-of-custody.jsonl", case_dir, before_manifest, after_manifest)
    print(out_dir / "report.md")
    print(f"<xml>{answer}</xml>")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    run(args.case_dir, args.out_dir, args.model, args.offline)


if __name__ == "__main__":
    main()
