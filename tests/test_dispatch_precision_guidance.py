from __future__ import annotations

import json
import shutil
from pathlib import Path

from esaa.security_audit import build_precision_dispatch_guidance, enrich_dispatch_context
from esaa.service import ESAAService


def test_baseline_workspace_has_no_precision_guidance(contract_bundle: Path) -> None:
    service = ESAAService(contract_bundle)
    service.init(force=True)
    context = service.dispatch_context("T-1000")
    assert "precision_guidance" not in context


def test_sec_task_dispatch_includes_precision_guidance(tmp_path: Path, repo_root: Path) -> None:
    shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
    service = ESAAService(tmp_path)
    service.init(force=True)

    context = service.dispatch_context("SEC-001")

    assert "precision_guidance" in context
    guidance = context["precision_guidance"]
    assert guidance["precision_policy"]["reject_code"] == "PRECISION_POLICY_VIOLATION"
    assert len(guidance["precision_policy"]["rules"]) >= 5
    assert guidance["tooling_decision"]["artifact"] == "reports/phase1/tool-capabilities.json"
    assert guidance["tooling_decision"]["artifact_present"] is False
    assert "prepare_for_complete" not in guidance or context["expected_action"] == "claim"


def test_impl_complete_includes_applicable_checks(tmp_path: Path, repo_root: Path) -> None:
    shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
    service = ESAAService(tmp_path)
    service.init(force=True)
    service.claim_task("SEC-015", actor="agent-impl")

    context = service.dispatch_context("SEC-015")

    assert context["expected_action"] == "complete"
    guidance = context["precision_guidance"]
    checks = guidance.get("applicable_checks", [])
    assert checks
    assert any(item["check_id"] == "IV-001" for item in checks)
    iv001 = next(item for item in checks if item["check_id"] == "IV-001")
    assert iv001.get("tooling", {}).get("preferred_tools")


def test_enrich_dispatch_context_with_tool_capabilities(tmp_path: Path, repo_root: Path) -> None:
    shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
    capabilities = {
        "artifact_version": "1.0.0",
        "generated_at": "2026-06-24T12:00:00Z",
        "run_id": "RUN-SEC-0001",
        "environment": {"os": "linux", "shell": "bash"},
        "utilities": [{"name": "grep", "status": "available"}],
        "optional_tools": [
            {"name": "gitleaks", "status": "available"},
            {"name": "semgrep", "status": "unavailable"},
        ],
    }
    (tmp_path / "reports" / "phase1").mkdir(parents=True)
    (tmp_path / "reports" / "phase1" / "tool-capabilities.json").write_text(
        json.dumps(capabilities),
        encoding="utf-8",
    )

    task = {
        "task_id": "SEC-010",
        "task_kind": "impl",
        "status": "in_progress",
        "playbook_ref": "secrets_config",
        "checks_covered": ["SC-001", "SC-002"],
        "execution_notes": "Use tool-capabilities.json for optional tooling.",
    }
    context = {
        "expected_action": "complete",
        "task": task,
    }
    enriched = enrich_dispatch_context(tmp_path, context, capabilities)

    decision = enriched["precision_guidance"]["tooling_decision"]
    assert decision["artifact_present"] is True
    assert "gitleaks" in decision["available_tools"]
    assert "semgrep" in decision["unavailable_tools"]


def test_sec030_complete_includes_consolidation_rules(tmp_path: Path, repo_root: Path) -> None:
    guidance = build_precision_dispatch_guidance(
        repo_root,
        {
            "task_id": "SEC-030",
            "task_kind": "qa",
            "status": "in_progress",
        },
        "complete",
        None,
    )
    assert guidance is not None
    assert guidance["consolidation"]["required_field"] == "evidence_sources"