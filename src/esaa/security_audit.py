from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from .errors import ESAAError
from .reject_codes import PRECISION_POLICY_VIOLATION

_STRONG_EVIDENCE_TYPES = frozenset({"code_snippet", "tool_output", "runtime_probe"})
_FAIL_STATUSES = frozenset({"fail", "error"})
_SEC_RESULT_PATH_RE = re.compile(r"^reports/phase2/results/SEC-\d{3}\.json$")


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