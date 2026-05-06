import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_runner import validate_plan as validate_synthetic_plan
from benchmark_runner import validate_plan as validate_benchmark_plan
from case_investigator import evidence_manifest, write_chain_of_custody


def test_synthetic_runner_rejects_shell_tool() -> None:
    with pytest.raises(ValueError, match="unsupported tool"):
        validate_synthetic_plan([{"tool": "shell", "goal": "read everything", "reason": "bypass"}])


def test_synthetic_runner_requires_claim_guard() -> None:
    with pytest.raises(ValueError, match="claim_guard"):
        validate_synthetic_plan([{"tool": "grep_auth", "goal": "check auth", "reason": "triage"}])


def test_benchmark_runner_requires_claim_guard_final() -> None:
    with pytest.raises(ValueError, match="claim_guard must be final"):
        validate_benchmark_plan(
            [
                {"tool": "claim_guard", "goal": "guard", "reason": "too early"},
                {"tool": "detect_obfuscation", "goal": "detect", "reason": "late"},
            ]
        )


def test_chain_of_custody_rejects_evidence_spoliation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "auth.log"
    artifact.write_text("before\n", encoding="utf-8")
    before = evidence_manifest(evidence)
    artifact.write_text("after\n", encoding="utf-8")
    after = evidence_manifest(evidence)

    with pytest.raises(RuntimeError, match="evidence changed"):
        write_chain_of_custody(tmp_path / "chain.jsonl", evidence, before, after)
