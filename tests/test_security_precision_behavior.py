from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _all_checks(playbooks: dict) -> list[tuple[str, dict]]:
    checks: list[tuple[str, dict]] = []
    for playbook_name, playbook in playbooks["playbooks"].items():
        for check in playbook["checks"]:
            checks.append((playbook_name, check))
    return checks


def _sample_tool_capabilities() -> dict:
    return {
        "artifact_version": "1.0.0",
        "generated_at": "2026-06-24T12:00:00Z",
        "run_id": "RUN-SEC-0001",
        "environment": {
            "os": "linux",
            "os_version": "6.8.0",
            "shell": "bash",
            "repo_path": "/tmp/target-repo",
        },
        "utilities": [
            {"name": "grep", "status": "available", "version": "3.11"},
            {"name": "find", "status": "available"},
        ],
        "optional_tools": [
            {
                "name": "gitleaks",
                "status": "unavailable",
                "capability_class": "secrets_scanners",
                "detection_method": "command -v gitleaks",
            },
            {
                "name": "semgrep",
                "status": "available",
                "version": "1.72.0",
                "capability_class": "sast_pattern_scanners",
            },
        ],
        "capability_classes_detected": ["sast_pattern_scanners"],
    }


def consolidate_sec030_findings(findings: list[dict]) -> list[dict]:
    """Contract-level dedup used to validate SEC-030 consolidation semantics."""
    merged: dict[tuple[str, str | None, str | None], dict] = {}
    for finding in findings:
        key = (
            finding["source_check"],
            finding.get("file"),
            finding.get("line"),
        )
        if key in merged:
            existing = merged[key]
            for source in finding.get("evidence_sources", []):
                if source not in existing["evidence_sources"]:
                    existing["evidence_sources"].append(source)
        else:
            merged[key] = {
                **finding,
                "evidence_sources": list(finding.get("evidence_sources", [])),
            }
    return list(merged.values())


def test_tool_capabilities_schema_validates_sample_artifact(repo_root: Path) -> None:
    schema = _load_json(repo_root / ".roadmap/tool-capabilities.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(_sample_tool_capabilities()), key=lambda e: e.path)
    assert not errors, [error.message for error in errors]


def test_tool_capabilities_schema_is_referenced_by_contracts(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")
    roadmap = _load_json(repo_root / ".roadmap/roadmap.security.json")
    sec001 = next(task for task in roadmap["tasks"] if task["task_id"] == "SEC-001")

    assert (
        playbooks["execution_policy"]["tooling_policy"]["detection_schema"]
        == ".roadmap/tool-capabilities.schema.json"
    )
    assert any(
        "tool-capabilities.schema.json" in criterion
        for criterion in sec001["acceptance_criteria"]
    )


def test_report_template_references_108_checks(repo_root: Path) -> None:
    report_template = _load_json(repo_root / ".roadmap/report-template.security.json")
    description = report_template["report_schema"]["appendix"]["fields"]["full_check_results"][
        "description"
    ]
    assert "108 checks" in description
    assert "95 checks" not in description


def test_missing_optional_tool_must_not_force_fail(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")
    policy = playbooks["execution_policy"]

    tool_rule = policy["tooling_policy"]["confidence_rule"].lower()
    assert "nunca" in tool_rule or "never" in tool_rule
    assert "fail" in tool_rule

    unavailable = policy["fallback_policy"]["tool_unavailable"].lower()
    assert "partial" in unavailable or "static_analysis" in unavailable
    assert "fail" not in unavailable.split("status=")[-1][:20]


def test_hybrid_without_endpoint_stays_static_first(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")
    policy = playbooks["execution_policy"]

    hybrid = policy["strategy_definitions"]["hybrid"].lower()
    assert "endpoint_not_provided" in hybrid or "not_applicable" in hybrid
    assert "não é falha" in hybrid or "not" in hybrid

    endpoint_fallback = policy["fallback_policy"]["endpoint_unavailable"].lower()
    assert "not_applicable" in endpoint_fallback
    assert "não é falha" in endpoint_fallback or "not" in endpoint_fallback


def test_missing_tool_capabilities_artifact_keeps_audit_valid(repo_root: Path) -> None:
    roadmap = _load_json(repo_root / ".roadmap/roadmap.security.json")
    note = roadmap["execution_strategy"]["fallback_policy"][
        "tool_capabilities_artifact_missing"
    ].lower()
    assert "continua válida" in note or "continues" in note or "válida" in note
    assert "estático" in note or "static" in note


@pytest.mark.parametrize(
    ("strategy", "expected_status"),
    [
        ("tool_unavailable", "partial"),
        ("endpoint_unavailable", "not_applicable"),
    ],
)
def test_fallback_policies_declare_non_fail_degradation(
    repo_root: Path, strategy: str, expected_status: str
) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")
    rule = playbooks["execution_policy"]["fallback_policy"][strategy].lower()
    assert expected_status in rule


def test_tooling_coverage_meets_expanded_target(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")
    tooling_count = sum(
        1 for _, check in _all_checks(playbooks) if check["agent_instructions"].get("tooling")
    )
    assert tooling_count >= 30


def test_checks_with_tooling_never_penalize_absence_as_fail(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")

    for playbook_name, check in _all_checks(playbooks):
        tooling = check["agent_instructions"].get("tooling")
        if not tooling:
            continue
        effect = tooling["confidence_effect"].lower()
        fallback = tooling["fallback_mode"]
        assert fallback in {"static_analysis", "partial"} or fallback.startswith(
            ("static_", "partial_")
        )
        assert "vira fail" not in effect
        assert "transforma o check em fail" not in effect
        assert "turns the check into fail" not in effect


def test_sec030_consolidation_deduplicates_multi_source_same_check() -> None:
    findings = [
        {
            "finding_id": "SEC-015-IV-001-001",
            "source_check": "IV-001",
            "file": "src/db.py",
            "line": "42",
            "evidence_sources": ["static_analysis"],
        },
        {
            "finding_id": "SEC-015-IV-001-001-TOOL",
            "source_check": "IV-001",
            "file": "src/db.py",
            "line": "42",
            "evidence_sources": ["semgrep"],
        },
        {
            "finding_id": "SEC-015-IV-001-001-RUNTIME",
            "source_check": "IV-001",
            "file": "src/db.py",
            "line": "42",
            "evidence_sources": ["runtime_probe"],
        },
        {
            "finding_id": "SEC-015-IV-002-001",
            "source_check": "IV-002",
            "file": "src/api.py",
            "line": "9",
            "evidence_sources": ["static_analysis"],
        },
    ]

    consolidated = consolidate_sec030_findings(findings)

    assert len(consolidated) == 2
    iv001 = next(item for item in consolidated if item["source_check"] == "IV-001")
    assert sorted(iv001["evidence_sources"]) == [
        "runtime_probe",
        "semgrep",
        "static_analysis",
    ]


def test_sec030_roadmap_declares_dedup_and_evidence_sources(repo_root: Path) -> None:
    roadmap = _load_json(repo_root / ".roadmap/roadmap.security.json")
    sec030 = next(task for task in roadmap["tasks"] if task["task_id"] == "SEC-030")

    notes = " ".join(
        [
            sec030["description"],
            " ".join(sec030["acceptance_criteria"]),
            sec030["execution_notes"],
        ]
    ).lower()

    assert "evidence_sources" in notes
    assert "duplic" in notes or "dedup" in notes or "único finding" in notes