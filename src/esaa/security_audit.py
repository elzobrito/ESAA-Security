from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from .errors import ESAAError
from .reject_codes import PRECISION_POLICY_VIOLATION
from .seeds import find_planned_plugin_task

_STRONG_EVIDENCE_TYPES = frozenset({"code_snippet", "tool_output", "runtime_probe"})
_FAIL_STATUSES = frozenset({"fail", "error"})
_SEC_RESULT_PATH_RE = re.compile(r"^reports/phase2/results/SEC-\d{3}\.json$")
_SEC_TASK_ID_RE = re.compile(r"^SEC-\d{3}$")

_PRECISION_DISPATCH_RULES = (
    "fallback_applied=true must never coexist with status=fail or error.",
    "confidence=high on fail requires evidence_types containing code_snippet, tool_output, or runtime_probe.",
    "When endpoint_base_url is absent, hybrid checks complete only the static portion; runtime portions use not_applicable.",
    "When optional tools are unavailable, degrade to static_analysis or partial; never fail solely because tooling is missing.",
    "Populate evidence.fallback_applied and evidence.fallback_reason whenever tooling or runtime confirmation was skipped.",
    "SEC-030 must consolidate multi-source evidence for the same check/root cause into one finding_id.",
)


def _security_audit_workspace(root: Path) -> bool:
    return (root / ".roadmap" / "playbooks.security.json").is_file()


def _load_security_playbooks(root: Path) -> dict[str, Any] | None:
    path = root / ".roadmap" / "playbooks.security.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _tooling_decision_summary(tool_capabilities: dict[str, Any] | None) -> dict[str, Any]:
    if not tool_capabilities:
        return {
            "artifact": "reports/phase1/tool-capabilities.json",
            "artifact_present": False,
            "decision": "Assume shell-only static analysis; do not invoke optional scanners unless already verified locally.",
        }

    optional = tool_capabilities.get("optional_tools") or []
    available = [item["name"] for item in optional if item.get("status") == "available"]
    unavailable = [item["name"] for item in optional if item.get("status") == "unavailable"]
    return {
        "artifact": "reports/phase1/tool-capabilities.json",
        "artifact_present": True,
        "available_tools": available,
        "unavailable_tools": unavailable,
        "decision": (
            "Use optional tools only when status=available in the artifact; "
            "otherwise apply the playbook fallback_mode without failing the check."
        ),
    }


def _check_dispatch_hints(check: dict[str, Any]) -> dict[str, Any]:
    instructions = check.get("agent_instructions", {})
    hint: dict[str, Any] = {
        "check_id": check.get("check_id"),
        "strategy": instructions.get("strategy"),
        "severity_if_fail": check.get("severity_if_fail"),
    }
    tooling = instructions.get("tooling")
    if isinstance(tooling, dict):
        hint["tooling"] = {
            "preferred_tools": tooling.get("preferred_tools", []),
            "fallback_mode": tooling.get("fallback_mode"),
            "capability_requirement": tooling.get("capability_requirement"),
        }
    return hint


def _checks_for_task(task: dict[str, Any], playbooks: dict[str, Any]) -> list[dict[str, Any]]:
    playbook_ref = task.get("playbook_ref")
    if not playbook_ref:
        return []

    playbook = playbooks.get("playbooks", {}).get(playbook_ref)
    if not isinstance(playbook, dict):
        return []

    covered = {str(item) for item in task.get("checks_covered", [])}
    hints: list[dict[str, Any]] = []
    for check in playbook.get("checks", []):
        check_id = str(check.get("check_id", ""))
        if covered and check_id not in covered:
            continue
        hints.append(_check_dispatch_hints(check))
    return hints


def build_precision_dispatch_guidance(
    root: Path,
    task: dict[str, Any],
    expected_action: str,
    tool_capabilities: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not _security_audit_workspace(root):
        return None

    task_id = str(task.get("task_id", ""))
    if not _SEC_TASK_ID_RE.match(task_id):
        return None

    planned = find_planned_plugin_task(root, task_id)
    if planned:
        task = {**planned, **task}

    guidance: dict[str, Any] = {
        "precision_policy": {
            "priority": "precision_first",
            "enforcement": "orchestrator_rejects_invalid_sec_results_at_submit",
            "reject_code": PRECISION_POLICY_VIOLATION,
            "rules": list(_PRECISION_DISPATCH_RULES),
        },
        "tooling_decision": _tooling_decision_summary(tool_capabilities),
    }

    execution_notes = task.get("execution_notes")
    if isinstance(execution_notes, str) and execution_notes.strip():
        guidance["execution_notes"] = execution_notes.strip()

    if task_id == "SEC-001" and expected_action == "complete":
        guidance["required_artifacts"] = [
            "reports/phase1/tech-stack-inventory.md",
            "reports/phase1/tool-capabilities.json",
        ]
        guidance["artifact_schema"] = ".roadmap/tool-capabilities.schema.json"

    if task_id == "SEC-030" and expected_action == "complete":
        guidance["consolidation"] = {
            "goal": "One finding_id per logical vulnerability even when confirmed by code, tooling, and runtime.",
            "required_field": "evidence_sources",
            "dedup_key": ["source_check", "file", "line"],
        }

    if task_id == "SEC-031" and expected_action == "complete":
        guidance["classification"] = {
            "reclassify_low_confidence_to_info": True,
            "do_not_promote_medium_without_strong_corroboration": True,
        }

    if expected_action == "complete" and task.get("task_kind") == "impl":
        playbooks = _load_security_playbooks(root)
        if playbooks:
            checks = _checks_for_task(task, playbooks)
            if checks:
                guidance["applicable_checks"] = checks

    if expected_action == "claim" and task.get("task_kind") == "impl":
        guidance["prepare_for_complete"] = (
            "Before completing, read reports/phase1/tool-capabilities.json when available and "
            "apply playbook fallback_mode deterministically for each check."
        )

    return guidance


def enrich_dispatch_context(
    root: Path,
    context: dict[str, Any],
    tool_capabilities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    task = context.get("task")
    if not isinstance(task, dict):
        return context

    guidance = build_precision_dispatch_guidance(
        root,
        task,
        str(context.get("expected_action", "none")),
        tool_capabilities,
    )
    if guidance:
        return {**context, "precision_guidance": guidance}
    return context


def _load_tool_capabilities_schema(root: Path) -> dict[str, Any]:
    path = root / ".roadmap" / "tool-capabilities.schema.json"
    if not path.is_file():
        raise ESAAError("SCHEMA_MISSING", f"missing schema: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_error_message(exc: ValidationError) -> str:
    path = "/".join(str(part) for part in exc.absolute_path) or "<root>"
    return f"{path}: {exc.message.splitlines()[0][:140]}"


def _validate_tool_capabilities_payload(root: Path, payload: dict[str, Any]) -> None:
    schema = _load_tool_capabilities_schema(root)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: item.path)
    if errors:
        raise ESAAError("SCHEMA_INVALID", _schema_error_message(errors[0]))


def _collect_check_results(payload: Any) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(payload, dict):
        raise ESAAError("SCHEMA_INVALID", "security result JSON must be an object")

    if isinstance(payload.get("results"), list):
        checks = payload["results"]
    elif isinstance(payload.get("checks"), list):
        checks = payload["checks"]
    else:
        return []

    collected: list[tuple[str, dict[str, Any]]] = []
    for item in checks:
        if not isinstance(item, dict):
            raise ESAAError("SCHEMA_INVALID", "security check result entries must be objects")
        check_id = str(item.get("check_id") or item.get("check_name") or "unknown")
        collected.append((check_id, item))
    return collected


def _validate_check_precision(check_id: str, check: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    status = str(check.get("status", "")).lower()
    confidence = str(check.get("confidence", "")).lower()
    evidence = check.get("evidence") if isinstance(check.get("evidence"), dict) else {}
    evidence_types = {
        str(item).lower()
        for item in (evidence.get("evidence_types") or [])
        if isinstance(item, str)
    }
    fallback_applied = evidence.get("fallback_applied")
    fallback_reason = str(evidence.get("fallback_reason") or "").lower()

    if fallback_applied is True and status in _FAIL_STATUSES:
        violations.append(
            f"{check_id}: fallback_applied=true cannot coexist with status={status}"
        )

    if status in _FAIL_STATUSES and confidence == "high" and not evidence_types & _STRONG_EVIDENCE_TYPES:
        violations.append(
            f"{check_id}: confidence=high with status={status} requires "
            "evidence_types containing code_snippet, tool_output, or runtime_probe"
        )

    if (
        status in _FAIL_STATUSES
        and "endpoint_not_provided" in fallback_reason
        and not evidence_types & {"code_snippet", "config_artifact", "tool_output"}
    ):
        violations.append(
            f"{check_id}: runtime unavailable (endpoint_not_provided) cannot justify "
            f"status={status} without static evidence"
        )

    return violations


def validate_security_result_payload(payload: Any, *, source: str) -> None:
    violations: list[str] = []
    for check_id, check in _collect_check_results(payload):
        violations.extend(_validate_check_precision(check_id, check))
    if violations:
        joined = "; ".join(violations[:5])
        if len(violations) > 5:
            joined += f"; +{len(violations) - 5} more"
        raise ESAAError(
            PRECISION_POLICY_VIOLATION,
            f"{source}: precision policy violation: {joined}",
        )


def validate_security_activity_event(event: dict[str, Any]) -> None:
    audit = event.get("security_audit")
    if not isinstance(audit, dict):
        return

    observations = audit.get("tooling_observations")
    if not isinstance(observations, list):
        return

    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise ESAAError("SCHEMA_INVALID", f"tooling_observations[{index}] must be an object")
        if observation.get("fallback_applied") is True and not observation.get("fallback_reason"):
            raise ESAAError(
                PRECISION_POLICY_VIOLATION,
                f"tooling_observations[{index}].fallback_reason is required when fallback_applied=true",
            )
        effect = str(observation.get("confidence_effect") or "").lower()
        if observation.get("fallback_applied") is True and "vira fail" in effect:
            raise ESAAError(
                PRECISION_POLICY_VIOLATION,
                f"tooling_observations[{index}] cannot promote fallback into fail",
            )


def validate_security_file_updates(root: Path, updates: list[dict[str, Any]]) -> None:
    for item in updates:
        path = str(item.get("path", "")).replace("\\", "/")
        content = item.get("content")
        if not isinstance(content, str):
            continue

        if path == "reports/phase1/tool-capabilities.json":
            try:
                payload = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ESAAError("SCHEMA_INVALID", f"invalid tool-capabilities.json: {exc}") from exc
            if not isinstance(payload, dict):
                raise ESAAError("SCHEMA_INVALID", "tool-capabilities.json must be a JSON object")
            _validate_tool_capabilities_payload(root, payload)
            continue

        if _SEC_RESULT_PATH_RE.match(path):
            try:
                payload = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ESAAError("SCHEMA_INVALID", f"invalid security result JSON at {path}: {exc}") from exc
            validate_security_result_payload(payload, source=path)