from __future__ import annotations

import json
from pathlib import Path


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _all_checks(playbooks: dict) -> list[tuple[str, dict]]:
    checks: list[tuple[str, dict]] = []
    for playbook_name, playbook in playbooks["playbooks"].items():
        for check in playbook["checks"]:
            checks.append((playbook_name, check))
    return checks


def test_security_counts_are_consistent(repo_root: Path) -> None:
    roadmap = _load_json(repo_root / ".roadmap/roadmap.security.json")
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")
    readme = (repo_root / "readme.md").read_text(encoding="utf-8")

    total_checks = sum(len(playbook["checks"]) for playbook in playbooks["playbooks"].values())
    impl_tasks = [task for task in roadmap["tasks"] if task["task_kind"] == "impl"]

    assert total_checks == 108
    assert len(playbooks["playbooks"]) == 17
    assert len(roadmap["tasks"]) == 27
    assert len(impl_tasks) == 17
    assert roadmap["meta"]["schema_version"] == "0.6.0"
    assert playbooks["metadata"]["version"] == "1.2.1"
    assert "108 executable checks across 27 tasks in 4 phases" in readme
    assert "17 security domains" in readme


def test_high_and_critical_checks_have_false_positive_guidance(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")

    missing: list[str] = []
    for playbook_name, check in _all_checks(playbooks):
        if check["severity_if_fail"] in {"HIGH", "CRITICAL"}:
            guidance = check["agent_instructions"].get("false_positive_guidance", "").strip()
            if not guidance:
                missing.append(f"{playbook_name}:{check['check_id']}")

    assert not missing, f"missing false_positive_guidance: {missing}"


def test_all_checks_define_confidence_guidance(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")

    missing: list[str] = []
    for playbook_name, check in _all_checks(playbooks):
        guidance = check["agent_instructions"].get("confidence_guidance", "").strip()
        if not guidance:
            missing.append(f"{playbook_name}:{check['check_id']}")

    assert not missing, f"missing confidence_guidance: {missing}"


def test_optional_tooling_contract_is_well_formed(repo_root: Path) -> None:
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")

    checks_with_tooling = 0
    for _, check in _all_checks(playbooks):
        tooling = check["agent_instructions"].get("tooling")
        if not tooling:
            continue
        checks_with_tooling += 1
        assert tooling["preferred_tools"]
        assert tooling["fallback_mode"]
        assert tooling["capability_requirement"]
        assert tooling["evidence_requirements"]
        assert tooling["confidence_effect"]

    assert checks_with_tooling >= 30


def test_tool_capabilities_schema_file_exists(repo_root: Path) -> None:
    schema_path = repo_root / ".roadmap/tool-capabilities.schema.json"
    assert schema_path.is_file()
    schema = _load_json(schema_path)
    assert schema["title"] == "ESAA Security Tool Capabilities Artifact"
    assert schema["properties"]["optional_tools"]["items"]["$ref"] == "#/$defs/capability_entry"


def test_phase1_tool_capabilities_are_wired_into_phase2(repo_root: Path) -> None:
    roadmap = _load_json(repo_root / ".roadmap/roadmap.security.json")
    playbooks = _load_json(repo_root / ".roadmap/playbooks.security.json")

    sec001 = next(task for task in roadmap["tasks"] if task["task_id"] == "SEC-001")
    assert "reports/phase1/tool-capabilities.json" in sec001["outputs"]["files"]

    for task in roadmap["tasks"]:
        if task["task_kind"] != "impl":
            continue
        assert "reports/phase1/tool-capabilities.json" in task["targets"]
        assert "tool-capabilities.json" in task["execution_notes"]

    assert "tool_capabilities_path" in playbooks["global_input_contract"]["optional"]
    assert (
        playbooks["execution_policy"]["tooling_policy"]["detection_artifact"]
        == "reports/phase1/tool-capabilities.json"
    )
    assert (
        playbooks["execution_policy"]["tooling_policy"]["detection_schema"]
        == ".roadmap/tool-capabilities.schema.json"
    )


def test_report_template_and_agent_schema_capture_multi_source_evidence(repo_root: Path) -> None:
    agent_schema = _load_json(repo_root / ".roadmap/agent_result.schema.json")
    report_template = _load_json(repo_root / ".roadmap/report-template.security.json")

    security_audit = agent_schema["properties"]["activity_event"]["properties"]["security_audit"]
    evidence_fields = report_template["report_schema"]["detailed_analysis"]["per_domain"]["checks"]["item_schema"][
        "evidence"
    ]["fields"]

    assert "tooling_observations" in security_audit["properties"]
    assert "tool_capabilities_summary" in report_template["report_schema"]["header"]["target"]
    assert "evidence_sources" in report_template["report_schema"]["vulnerability_matrix"]["columns"]
    assert "evidence_types" in evidence_fields
    assert "tool_name" in evidence_fields
    assert "fallback_applied" in evidence_fields
