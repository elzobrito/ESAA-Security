---
name: esaa-security
description: >
  Operate and extend ESAA-Security: static-first security audits with event-sourced
  governance, 108 checks across 17 domains, precision enforcement, and esaa-core CLI.
  Use when auditing repos, executing SEC tasks, editing playbooks or roadmap contracts,
  fixing PRECISION_POLICY_VIOLATION rejections, working on security_audit.py, dispatch-context,
  tool-capabilities.json, or running security tests. Triggers: ESAA-Security, security audit,
  SEC-NNN, playbooks.security, precision policy, /esaa-security.
metadata:
  short-description: "ESAA-Security audit and development workflow"
---

# ESAA-Security

Guide work inside this repository: governed security audits, contract changes, and runtime enforcement.

Read `references/contracts.md` when you need exact paths, schemas, or precision rules.

## When to use

| User intent | Action |
|---|---|
| Run or continue an audit | Follow **Audit workflow** |
| Change playbooks, roadmap, schemas | Follow **Contract changes** + run security tests |
| Fix rejected SEC results | Follow **Precision policy** |
| Develop runtime/orchestrator code | Follow **Development** |
| Understand dispatch context | Run `dispatch-context` and read `precision_guidance` |

## Core principles

1. **Static-first** — default mode inspects local source and versioned config. Optional tools deepen confirmation; their absence must not cause fail.
2. **Agents investigate; orchestrator adjudicates** — agents emit structured results; only the orchestrator appends events and writes governed files.
3. **Precision over recall** — heuristic checks express uncertainty via `confidence`, `partial`, and `fallback_applied`; runtime rejects invalid combinations.
4. **Traceability** — every finding must map to events in `.roadmap/activity.jsonl` and check results under `reports/phase2/results/`.

## Audit workflow

### 1. Bootstrap and inspect state

```bash
pip install -e ".[dev]"
python -m esaa --root . bootstrap --profile public
python -m esaa --root . init --runner <codex|claude|gemini>
python -m esaa --root . eligible
python -m esaa --root . state SEC-001
python -m esaa --root . dispatch-context SEC-001
```

### 2. Required inputs

Provide at minimum:

```yaml
repo_path: /absolute/path/to/target/repo
```

Optional:

```yaml
endpoint_base_url: http://localhost:3000   # confirmatory hybrid checks only
tool_capabilities_path: .../reports/phase1/tool-capabilities.json
```

When `endpoint_base_url` is absent, hybrid checks run static portions only; runtime portions use `not_applicable`.

### 3. Phase execution

| Phase | Tasks | Agent role | Key outputs |
|---|---|---|---|
| 1 Recon | SEC-001 → SEC-003 | spec | `tech-stack-inventory.md`, `tool-capabilities.json`, architecture/surface maps |
| 2 Audit | SEC-010 → SEC-026 | impl | `reports/phase2/{domain}-audit.md`, `reports/phase2/results/SEC-NNN.json` |
| 3 Risk | SEC-030 → SEC-032 | qa | vulnerability inventory, risk matrix |
| 4 Report | SEC-040 → SEC-043 | spec/qa | remediations, executive summary, final report |

### 4. Per-task agent loop

For each eligible SEC task:

1. Read `.roadmap/roadmap.json` (runtime progress) and `.roadmap/roadmap.security.json` (versioned contract).
2. Run `dispatch-context SEC-NNN` and follow `precision_guidance`.
3. Read the playbook from `.roadmap/playbooks.security.json` (`playbook_ref`, `checks_covered`, `execution_notes`).
4. Execute checks in **static-first** mode; use optional tools only when `tool-capabilities.json` marks them `available`.
5. Emit structured check results (status, severity, confidence, evidence, remediation).
6. Transition: `claim` → `complete` → `review` via orchestrator (not direct file writes outside boundaries).
7. Verify: `python -m esaa --root . verify`

### 5. Monitor and finalize

```bash
cat .roadmap/roadmap.json
cat .roadmap/activity.jsonl
cat reports/final/security-audit-report.md
```

## Precision policy

The orchestrator enforces these rules at submit time (`src/esaa/security_audit.py`). Violations return `PRECISION_POLICY_VIOLATION`.

| Rule | Requirement |
|---|---|
| Fallback + fail | `evidence.fallback_applied=true` cannot coexist with `status=fail` or `error` |
| High confidence fail | Requires `evidence_types` containing `code_snippet`, `tool_output`, or `runtime_probe` |
| Missing endpoint | Hybrid checks: static portion only; runtime → `not_applicable` |
| Missing tools | Degrade to `static_analysis` or `partial`; never fail solely because tooling is absent |
| Skipped confirmation | Set `fallback_applied` and `fallback_reason` when tooling/runtime was skipped |
| SEC-030 | One `finding_id` per logical vulnerability; use `evidence_sources` for multi-source dedup |

When fixing rejections, adjust the SEC result JSON — do not weaken enforcement in code unless the contract intentionally changed.

## Dispatch context

`dispatch-context SEC-NNN` adds `precision_guidance`:

- `precision_policy` — rules and reject code
- `tooling_decision` — available/unavailable optional tools from Phase 1
- `applicable_checks` — per-check strategy and tooling hints (impl tasks on complete)
- Task hints: SEC-001 (required artifacts + schema), SEC-030 (consolidation), SEC-031 (classification)

Always read this block before executing or completing an SEC task.

## Contract changes

When editing governance artifacts:

| File | Change impact |
|---|---|
| `.roadmap/playbooks.security.json` | Check instructions, tooling blocks, strategies (v1.2.1, 35 checks with tooling) |
| `.roadmap/roadmap.security.json` | Task graph, dependencies, checks_covered |
| `.roadmap/report-template.security.json` | Scoring and final report projection |
| `.roadmap/tool-capabilities.schema.json` | SEC-001 artifact validation |
| `src/esaa/security_audit.py` | Runtime precision enforcement and dispatch guidance |

After contract or enforcement changes, run the security test suite (below). Keep playbook `version` fields consistent when bumping.

## Development

### Install and test

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

### Security-focused tests

```bash
python -m pytest tests/test_security.py tests/test_security_contracts.py tests/test_security_precision_behavior.py tests/test_security_precision_enforcement.py tests/test_dispatch_precision_guidance.py -q
```

Expected baseline: **163 passed, 1 skipped** (symlink fixture skipped on Windows).

### Key runtime modules

| Module | Responsibility |
|---|---|
| `src/esaa/security_audit.py` | Precision validation, tool-capabilities schema, dispatch guidance |
| `src/esaa/submission.py` | File-update validation hook for SEC artifacts |
| `src/esaa/validator.py` | Activity event validation |
| `src/esaa/task_admin.py` | Dispatch context enrichment |
| `src/esaa/seeds.py` | Preserves `playbook_ref`, `checks_covered`, `execution_notes` |

### Change checklist

1. Read surrounding code; match existing patterns.
2. Implement minimal diff for the requested behavior.
3. Add or update tests in `tests/test_security*.py` or `tests/test_dispatch_precision_guidance.py`.
4. Run targeted tests, then full suite.
5. Update `readme.md` only if user-facing contracts or workflows changed.

## Boundaries

- Do not let agents write directly to `.roadmap/activity.jsonl` or mutate `roadmap.json` outside orchestrator events.
- SEC result files must match `reports/phase2/results/SEC-NNN.json`.
- `tool-capabilities.json` must validate against `.roadmap/tool-capabilities.schema.json`.
- Prefer POSIX-like environments (Linux/WSL2) for shell-based static analysis and optional AppSec tools.

## Common CLI reference

```bash
python -m esaa --root . eligible
python -m esaa --root . dispatch-context SEC-015
python -m esaa --root . claim SEC-015 --actor agent-impl
python -m esaa --root . complete SEC-015 --actor agent-impl --checks "..."
python -m esaa --root . review SEC-015 --actor agent-qa --outcome pass
python -m esaa --root . verify
python -m esaa --root . project
```

Use `--root .` from the ESAA-Security workspace root unless auditing a bootstrapped target workspace.