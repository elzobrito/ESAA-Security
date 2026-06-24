# ESAA-Security Contracts Reference

Quick reference for paths, versions, and enforcement details.

## Versions (current)

| Artifact | Version |
|---|---|
| Roadmap contract | `.roadmap/roadmap.security.json` — schema v0.6.0 |
| Playbooks | `.roadmap/playbooks.security.json` — v1.2.1 (35 checks with `tooling` blocks) |
| Checks | 108 across 17 domains, 27 tasks, 4 phases |
| Tool capabilities schema | `.roadmap/tool-capabilities.schema.json` |

## Repository layout

```
.roadmap/
  activity.jsonl              # append-only event store
  roadmap.json                # runtime projection (derived)
  roadmap.security.json       # versioned audit contract
  playbooks.security.json     # agent-executable checks
  tool-capabilities.schema.json
  report-template.security.json
  agent_result.schema.json
  AGENT_CONTRACT.yaml
  ORCHESTRATOR_CONTRACT.yaml

reports/
  phase1/tool-capabilities.json
  phase2/results/SEC-NNN.json
  phase3/                     # risk classification
  phase4/                     # remediations, executive summary
  final/security-audit-report.md

src/esaa/security_audit.py    # precision enforcement + dispatch guidance
```

## Security domains (17)

| Domain | Check IDs | Priority |
|---|---|---|
| Secrets & Configuration | SC-001 → SC-008 | critical |
| Dependencies & Supply Chain | DS-001 → DS-006 | high |
| Authentication | AU-001 → AU-009 | critical |
| Authorization | AZ-001 → AZ-006 | critical |
| API Security | AP-001 → AP-009 | high |
| Input Validation | IV-001 → IV-010 | critical |
| File Upload | FU-001 → FU-006 | high |
| Session Security | SS-001 → SS-006 | high |
| Cryptography | CR-001 → CR-005 | high |
| Security Headers | SH-001 → SH-005 | medium |
| Logging & Monitoring | LM-001 → LM-005 | medium |
| Infrastructure | IF-001 → IF-007 | high |
| DevSecOps | DO-001 → DO-006 | medium |
| Data Security | DA-001 → DA-005 | critical |
| Frontend Security | FE-001 → FE-004 | medium |
| AI/LLM Security | AI-001 → AI-007 | high |
| Business Logic & Anti-Automation | BL-001 → BL-004 | high |

## Agent strategies

| Strategy | Count | Mode |
|---|---|---|
| `static_analysis` | 89 | Default: grep/find/config inspection |
| `hybrid` | 17 | Static-first + optional runtime when `endpoint_base_url` provided |
| `tool_execution` | 2 | Local tools (`npm audit`, `pip-audit`, etc.) |

## Precision dispatch rules

Enforced by `validate_security_result_payload` and `validate_security_file_updates`:

1. `fallback_applied=true` + `status=fail|error` → reject
2. `confidence=high` + `status=fail|error` without strong evidence types → reject
3. `endpoint_not_provided` fallback cannot justify fail without static evidence
4. `tool-capabilities.json` must pass JSON Schema on write
5. Activity `tooling_observations`: `fallback_reason` required when `fallback_applied=true`; effect cannot promote fallback to fail

Strong evidence types: `code_snippet`, `tool_output`, `runtime_probe`.

## SEC result shape (minimal)

```json
{
  "task_id": "SEC-015",
  "results": [
    {
      "check_id": "IV-001",
      "status": "fail",
      "confidence": "high",
      "evidence": {
        "files": ["src/example.py"],
        "lines": ["42: vulnerable pattern"],
        "evidence_types": ["code_snippet"],
        "fallback_applied": false,
        "description": "Concrete proof of the issue."
      },
      "remediation": "Use parameterized queries."
    }
  ]
}
```

Valid statuses: `pass`, `fail`, `partial`, `not_applicable`, `error`.

## Test files

| File | Covers |
|---|---|
| `tests/test_security.py` | Core security workspace behavior |
| `tests/test_security_contracts.py` | Roadmap/playbook/report contracts |
| `tests/test_security_precision_behavior.py` | Playbook precision semantics |
| `tests/test_security_precision_enforcement.py` | Runtime rejection rules |
| `tests/test_dispatch_precision_guidance.py` | `precision_guidance` in dispatch-context |

## Reject code

`PRECISION_POLICY_VIOLATION` — defined in `src/esaa/reject_codes.py`, raised from `src/esaa/security_audit.py`.