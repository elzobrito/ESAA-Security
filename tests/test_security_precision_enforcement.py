from __future__ import annotations

import json
from pathlib import Path

import pytest

from esaa.errors import ESAAError
from esaa.security_audit import (
    validate_security_activity_event,
    validate_security_file_updates,
    validate_security_result_payload,
)


def _valid_tool_capabilities() -> dict:
    return {
        "artifact_version": "1.0.0",
        "generated_at": "2026-06-24T12:00:00Z",
        "run_id": "RUN-SEC-0001",
        "environment": {"os": "linux", "shell": "bash"},
        "utilities": [{"name": "grep", "status": "available"}],
        "optional_tools": [{"name": "gitleaks", "status": "unavailable"}],
    }


def _sec_result(checks: list[dict]) -> dict:
    return {"task_id": "SEC-015", "results": checks}


def test_rejects_fail_when_fallback_applied() -> None:
    payload = _sec_result(
        [
            {
                "check_id": "IV-001",
                "status": "fail",
                "confidence": "medium",
                "evidence": {
                    "fallback_applied": True,
                    "fallback_reason": "tool_unavailable",
                    "evidence_types": ["code_snippet"],
                },
            }
        ]
    )
    with pytest.raises(ESAAError) as exc_info:
        validate_security_result_payload(payload, source="SEC-015.json")
    assert exc_info.value.code == "PRECISION_POLICY_VIOLATION"


def test_rejects_high_confidence_fail_without_strong_evidence() -> None:
    payload = _sec_result(
        [
            {
                "check_id": "AZ-001",
                "status": "fail",
                "confidence": "high",
                "evidence": {
                    "fallback_applied": False,
                    "evidence_types": ["doc_reference"],
                },
            }
        ]
    )
    with pytest.raises(ESAAError) as exc_info:
        validate_security_result_payload(payload, source="SEC-013.json")
    assert exc_info.value.code == "PRECISION_POLICY_VIOLATION"


def test_allows_partial_with_fallback_applied() -> None:
    payload = _sec_result(
        [
            {
                "check_id": "DS-001",
                "status": "partial",
                "confidence": "low",
                "evidence": {
                    "fallback_applied": True,
                    "fallback_reason": "tool_unavailable",
                    "evidence_types": ["config_artifact"],
                },
            }
        ]
    )
    validate_security_result_payload(payload, source="SEC-011.json")


def test_rejects_endpoint_missing_fail_without_static_evidence() -> None:
    payload = _sec_result(
        [
            {
                "check_id": "SH-001",
                "status": "fail",
                "confidence": "medium",
                "evidence": {
                    "fallback_applied": True,
                    "fallback_reason": "endpoint_not_provided",
                    "evidence_types": ["runtime_probe"],
                },
            }
        ]
    )
    with pytest.raises(ESAAError) as exc_info:
        validate_security_result_payload(payload, source="SEC-019.json")
    assert exc_info.value.code == "PRECISION_POLICY_VIOLATION"


def test_tool_capabilities_file_must_match_schema(tmp_path: Path, repo_root: Path) -> None:
    import shutil

    shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
    updates = [
        {
            "path": "reports/phase1/tool-capabilities.json",
            "content": json.dumps({"artifact_version": "9.9.9"}),
        }
    ]
    with pytest.raises(ESAAError) as exc_info:
        validate_security_file_updates(tmp_path, updates)
    assert exc_info.value.code == "SCHEMA_INVALID"


def test_valid_tool_capabilities_and_sec_result_pass_file_validation(
    tmp_path: Path, repo_root: Path
) -> None:
    import shutil

    shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
    updates = [
        {
            "path": "reports/phase1/tool-capabilities.json",
            "content": json.dumps(_valid_tool_capabilities()),
        },
        {
            "path": "reports/phase2/results/SEC-015.json",
            "content": json.dumps(
                _sec_result(
                    [
                        {
                            "check_id": "IV-002",
                            "status": "pass",
                            "confidence": "high",
                            "evidence": {
                                "fallback_applied": False,
                                "evidence_types": ["code_snippet"],
                            },
                        }
                    ]
                )
            ),
        },
    ]
    validate_security_file_updates(tmp_path, updates)


def test_tooling_observation_requires_fallback_reason_when_applied() -> None:
    with pytest.raises(ESAAError) as exc_info:
        validate_security_activity_event(
            {
                "action": "complete",
                "task_id": "SEC-015",
                "security_audit": {
                    "tooling_observations": [
                        {"check_id": "IV-001", "fallback_applied": True}
                    ]
                },
            }
        )
    assert exc_info.value.code == "PRECISION_POLICY_VIOLATION"


def test_sec_result_file_validation_rejects_fallback_fail_combo(tmp_path: Path, repo_root: Path) -> None:
    import shutil

    shutil.copytree(repo_root / ".roadmap", tmp_path / ".roadmap")
    updates = [
        {
            "path": "reports/phase2/results/SEC-015.json",
            "content": json.dumps(
                _sec_result(
                    [
                        {
                            "check_id": "IV-001",
                            "status": "fail",
                            "confidence": "high",
                            "evidence": {
                                "fallback_applied": True,
                                "fallback_reason": "tool_unavailable",
                                "evidence_types": ["code_snippet"],
                            },
                        }
                    ]
                )
            ),
        }
    ]
    with pytest.raises(ESAAError) as exc_info:
        validate_security_file_updates(tmp_path, updates)
    assert exc_info.value.code == "PRECISION_POLICY_VIOLATION"