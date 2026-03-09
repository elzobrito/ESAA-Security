# ESAA-Security — Autonomous Security Auditing with Event-Sourced Agents

> **Treat security audits as deterministic pipelines, not as free-form checklists.**

ESAA-Security is a **domain-specific specialization** of the [ESAA architecture](https://github.com/elzobrito/ESAA---Event-Sourcing-Agent-Architecture) for automated security auditing of software repositories, with particular emphasis on AI-generated or AI-modified code. The governance methodology — separating heuristic agent cognition from deterministic state mutation through append-only events, boundary contracts, constrained structured outputs, and replay-based verification — comes from ESAA itself. ESAA-Security inherits this kernel and redefines the artifact space around security evidence, playbook-driven domain coverage, and risk-oriented reporting. Every finding, classification, and remediation is recorded as a fact — the final report is a deterministic projection of the audit trail.

📄 **ESAA Paper:** [ESAA: Event Sourcing for Autonomous Agents in LLM-Based Software Engineering](https://arxiv.org/abs/2602.23193) — the governance kernel: event sourcing, deterministic orchestration, boundary contracts, replay verification
🔒 **ESAA-Security Paper:** [ESAA-Security: An Event-Sourced, Verifiable Architecture for Agent-Assisted Security Audits of AI-Generated Code](https://arxiv.org/abs/2603.06365) — the domain specialization: audit phases, security playbooks, risk-oriented outputs
🧩 **PARCER Paper:** [PARCER as an Operational Contract to Reduce Variance, Cost, and Risk in LLM Systems](https://arxiv.org/abs/2603.00856) — the operational contract: decision hygiene, adaptive budgeting, structured validation
🛡️ **Source Framework:** [PARCER v1.6.0 Security Auditor](docs/PARCER_v1.6.0-security-audit.yaml)

---

## Why ESAA-Security?

Security audits performed by LLM agents inherit all the structural problems of autonomous agents — plus domain-specific risks:

| Problem | How ESAA-Security solves it |
|---|---|
| **Hallucinated vulnerabilities** — agents invent findings that don't exist | Guardrails require technical evidence for every finding; playbooks define objective pass/fail criteria |
| **Inconsistent coverage** — agents skip domains or checks arbitrarily | 95 executable checks across 16 domains with dependency-ordered execution |
| **No audit trail** — impossible to verify what was actually tested | Every check result is an event in the append-only log; the report is a verifiable projection |
| **Non-reproducible results** — same system yields different findings each run | Deterministic replay + SHA-256 verification; same events always produce the same report |

Unlike ad-hoc "ask the LLM to review my code" approaches, ESAA-Security provides **structured playbooks**, **schema-validated results**, and **forensic traceability** from finding back to evidence.

### Architecture Lineage

ESAA-Security is built on three distinct layers, each with its own paper and contribution:

| Layer | Contribution | Paper |
|---|---|---|
| **ESAA** (governance kernel) | The methodology: append-only event store as source of truth, deterministic orchestrator that validates and persists agent intentions, boundary contracts per task kind, SHA-256 replay verification, "done" immutability, purified views for context injection. Validated with heterogeneous multi-agent orchestration (Claude Sonnet 4.6, Codex GPT-5, Gemini 3 Pro, Claude Opus 4.6). | [arXiv:2602.23193](https://arxiv.org/abs/2602.23193) |
| **PARCER** (operational contract) | Agent-level governance: declarative YAML contracts that enforce decision hygiene (7 procedures), adaptive token budgeting, context fallbacks (Map-Reduce/RAG), structured validation with hard gates, and OpenTelemetry observability. The PARCER profiles (`PARCER_PROFILE.agent-spec.yaml`, `agent-impl.yaml`, `agent-qa.yaml`) bind each agent role to its tool budget, verification requirements, and escalation rules. | [arXiv:2603.00856](https://arxiv.org/abs/2603.00856) |
| **ESAA-Security** (domain specialization) | The security audit pipeline: 4 phases (reconnaissance → domain audit → risk classification → reporting), 26 tasks, 16 security domains, 95 executable checks, structured findings with severity classification, risk matrices, remediation guidance, and executive reporting. The final report is not a free-form narrative — it is a projection of governed audit state. | [arXiv:2603.06365](https://arxiv.org/abs/2603.06365) |

The key insight is that security review should not be modeled as a prompting problem but as a **governed execution problem**. ESAA provides the mechanism (how state evolves). PARCER provides the agent discipline (how agents behave). ESAA-Security provides the domain semantics (what gets audited and how findings are structured).

---

## Architecture

```
┌─────────────┐   check_result    ┌──────────────────┐  append event  ┌─────────────┐
│  Audit Agent │ ───────────────► │   Orchestrator   │ ─────────────► │ Event Store │
│  (finding)   │                  │ (deterministic)  │                │  (.jsonl)   │
└─────────────┘ ◄─────────────── └──────────────────┘                └──────┬──────┘
       ▲         output.rejected        │                                   │
       │                                │                              project
       │         ┌──────────────┐       │                                   │
       │         │   Playbook   │       │                                   ▼
       │         │  + Contract  │  ┌────┴─────────┐                 ┌──────────────┐
       │         └──────────────┘  │ JSON Schema  │                 │  Read-Model  │
       │                           │  Validation  │                 │   (.json)    │
       │                           └──────────────┘                 └──────┬───────┘
       │                                                                   │
       └──────────────────── purified view ────────────────────────────────┘
```

**Core principle (inherited from ESAA):** Agents investigate, the Orchestrator adjudicates.

- **Agents** execute playbook checks and emit structured results (`agent_result`, `issue.report`) — they **cannot** write the report, mutate state, or append events directly.
- **Orchestrator** validates results against JSON Schema + boundary contracts, persists events, and projects the read-model.
- **Event Store** (`activity.jsonl`) records every check execution, finding, and classification as an immutable fact.
- **Read-Model** (`roadmap.json`) tracks audit progress — which checks passed, which failed, which domains are complete.

---

## Security Domains

ESAA-Security covers 16 security domains derived from the PARCER Security Auditor framework:

| Domain | Checks | Priority | Playbook IDs |
|---|---|---|---|
| Secrets & Configuration | 8 | critical | SC-001 → SC-008 |
| Authentication | 8 | critical | AU-001 → AU-008 |
| Authorization | 6 | critical | AZ-001 → AZ-006 |
| Input Validation | 7 | critical | IV-001 → IV-007 |
| Data Security | 5 | critical | DA-001 → DA-005 |
| Dependencies & Supply Chain | 6 | high | DS-001 → DS-006 |
| API Security | 7 | high | AP-001 → AP-007 |
| File Upload | 6 | high | FU-001 → FU-006 |
| Session Security | 6 | high | SS-001 → SS-006 |
| Cryptography | 5 | high | CR-001 → CR-005 |
| Infrastructure | 6 | high | IF-001 → IF-006 |
| AI/LLM Security | 5 | high | AI-001 → AI-005 |
| Security Headers | 5 | medium | SH-001 → SH-005 |
| Logging & Monitoring | 5 | medium | LM-001 → LM-005 |
| DevSecOps | 6 | medium | DO-001 → DO-006 |
| Frontend Security | 4 | medium | FE-001 → FE-004 |

**Total:** 95 executable checks across 26 tasks in 4 phases.

---

## Repository Structure

```
.roadmap/
├── activity.jsonl                              # Event store (append-only, source of truth)
├── roadmap.json                                # Read-model: audit progress (derived, verifiable)
├── issues.json                                 # Read-model: open/resolved audit issues
├── lessons.json                                # Read-model: learned constraints
├── snapshots/                                  # Integrity snapshots
│
├── AGENT_CONTRACT.yaml                         # What audit agents CAN and CANNOT do
├── ORCHESTRATOR_CONTRACT.yaml                  # Orchestrator invariants
├── RUNTIME_POLICY.yaml                         # TTLs, retries, escalation, rollback
├── STORAGE_POLICY.yaml                         # Event store format and field constraints
├── PROJECTION_SPEC.md                          # How events → state (pure function spec)
│
├── agent_result.schema.json                    # JSON Schema: validates every agent output
├── roadmap.schema.json                         # JSON Schema: validates roadmap.json (v0.4.0)
├── issues.schema.json                          # JSON Schema: validates issues.json
│
├── agents_swarm.yaml                           # Agent registry and role resolution
│
├── PARCER_PROFILE.agent-spec.yaml              # Profile: reconnaissance agent
├── PARCER_PROFILE.agent-impl.yaml              # Profile: audit execution agent
├── PARCER_PROFILE.agent-qa.yaml                # Profile: risk classification and reporting agent
└── PARCER_PROFILE.orchestrator-runtime.yaml    # Profile: orchestrator runtime

playbooks/
├── playbooks.security.json                     # Agent-executable playbooks (95 checks, 16 domains)
└── global_input_contract.json                  # Required/optional inputs for audit execution

reports/
├── phase1/                                     # Reconnaissance outputs
│   ├── tech-stack-inventory.md
│   ├── architecture-map.md
│   ├── data-flow-diagram.md
│   └── attack-surface-inventory.md
├── phase2/                                     # Audit execution outputs (boundary: agent-impl write)
│   ├── {domain}-audit.md                       # Narrative audit per domain
│   └── results/
│       └── SEC-{NNN}.json                      # Structured check results per task
├── phase3/                                     # Risk classification outputs (boundary: agent-qa write)
│   ├── vulnerability-inventory.json
│   ├── classified-vulnerabilities.json
│   ├── risk-matrix.json
│   └── risk-matrix.md
├── phase4/                                     # Recommendations and reporting
│   ├── technical-remediations.md
│   ├── best-practices.md
│   └── executive-summary.md
└── final/                                      # Final compiled report
    ├── security-audit-report.md
    └── security-audit-report.json
```

---

## Audit Phases

### Phase 1 — Reconnaissance (`spec` tasks)

Before any security check runs, the agent maps the terrain:

| Task | Output |
|---|---|
| SEC-001: Identify tech stack | Languages, frameworks, databases, cloud services, dependency versions |
| SEC-002: Map architecture | Components, data flows, integration points, trust boundaries |
| SEC-003: Enumerate attack surfaces | Endpoints, interfaces, uploads, websockets, external APIs |

These outputs feed every Phase 2 task via `depends_on`.

### Phase 2 — Audit Execution (`impl` tasks)

The core audit: 16 tasks, one per security domain. Each task executes the corresponding playbook:

```
Agent receives:  playbook (checks + agent_instructions) + reconnaissance outputs
Agent executes:  grep/find/curl commands per check, applies pass/fail criteria
Agent emits:     structured result per check (status, severity, evidence, remediation)
```

Example — check IV-001 (SQL Injection) from the `input_validation` playbook:

```json
{
  "check_id": "IV-001",
  "name": "SQL injection",
  "status": "fail",
  "severity_if_fail": "CRITICAL",
  "evidence": {
    "files": ["src/controllers/userController.js"],
    "lines": ["42: db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"],
    "description": "String interpolation in raw SQL query with unsanitized user input."
  },
  "remediation": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [req.params.id])"
}
```

### Phase 3 — Risk Classification (`qa` tasks)

Consolidates all Phase 2 findings into a prioritized risk matrix:

| Task | Output |
|---|---|
| SEC-030: Consolidate vulnerabilities | Unified inventory with IDs, domains, and evidence |
| SEC-031: Classify severity and impact | CRITICAL/HIGH/MEDIUM/LOW/INFO with CIA impact assessment |
| SEC-032: Generate risk matrix | Vulnerability × category × severity × impact × remediation |

### Phase 4 — Recommendations and Report (`spec` + `qa` tasks)

| Task | Output |
|---|---|
| SEC-040: Technical remediations | Code/config fixes for CRITICAL and HIGH findings |
| SEC-041: Best practices | Domain-organized practices with OWASP/CIS/NIST references |
| SEC-042: Executive summary | 1-page summary with security score (0-100) and top 5 risks |
| SEC-043: Final report | Complete audit report — all sections, all findings traceable to checks |

---

## Playbook Structure

Each of the 16 playbooks in `playbooks.security.json` follows this structure:

```json
{
  "task_ref": "SEC-015",
  "domain": "input_validation",
  "priority": "critical",
  "input_requirements": {
    "required": ["repo_path"],
    "optional": ["endpoint_base_url"]
  },
  "checks": [
    {
      "check_id": "IV-001",
      "name": "SQL injection",
      "severity_if_fail": "CRITICAL",
      "agent_instructions": {
        "strategy": "static_analysis",
        "steps": [
          "grep -rn ... (concrete commands)",
          "Verify ORM usage consistency",
          "Check raw queries for parameterization"
        ],
        "pass_criteria": "ORM used consistently. Raw queries use parameterization. Zero concatenation of input in SQL.",
        "fail_criteria": "Any concatenation of user input in SQL string. Raw queries without parameterization.",
        "false_positive_guidance": "ORM query builders that use parameterization internally are safe."
      },
      "remediation": "Use ORM or prepared statements. Never concatenate input in SQL."
    }
  ]
}
```

**Agent strategies:**

| Strategy | Count | Description |
|---|---|---|
| `static_analysis` | 77 | Grep/find patterns in source code and config files |
| `hybrid` | 16 | Static analysis + live endpoint testing (when `endpoint_base_url` available) |
| `tool_execution` | 2 | Run security tools (`npm audit`, `pip-audit`, etc.) |

Every check provides **objective pass/fail criteria** — the agent doesn't decide what counts as a vulnerability; the playbook defines it.

---

## Roadmap Schema Compliance

The audit roadmap (`roadmap.json`) conforms to the ESAA v0.4.0 canonical schema:

```json
{
  "meta": {
    "schema_version": "0.4.0",
    "immutable_done": true,
    "run": {
      "run_id": "RUN-SEC-0001",
      "status": "initialized",
      "last_event_seq": 0,
      "projection_hash_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "verify_status": "unknown"
    }
  },
  "project": {
    "name": "PARCER Security Audit",
    "audit_scope": "Full-stack security audit covering 16 domains..."
  },
  "tasks": [ ... ],
  "indexes": {
    "by_status": { "todo": 26, "in_progress": 0, "review": 0, "done": 0 },
    "by_kind": { "spec": 5, "impl": 16, "qa": 5 }
  }
}
```

All [ESAA invariants](https://arxiv.org/abs/2602.23193) apply:

- **`immutable_done: true`** — completed audit tasks cannot be modified; corrections require the hotfix workflow
- **`verify_status`** — SHA-256 replay verification after every state change
- **`additionalProperties: false`** — strict schema compliance at every level
- **Indexes consistent** — `by_status` and `by_kind` match actual task counts

---

## Task State Machine

The task lifecycle is defined by the [ESAA architecture](https://arxiv.org/abs/2602.23193) and enforces claim-before-work, done-immutability, and prior-status consistency invariants:

```
         claim              complete          review(approve)
[todo] ─────────► [in_progress] ─────────► [review] ─────────► [done] ✗
                       ▲                       │                   (immutable)
                       └───────────────────────┘
                          review(request_changes)
```

Applied to the security audit context:

- **`claim`** — Agent takes ownership of a security domain audit (e.g., SEC-015: Input Validation)
- **`complete`** — Agent finishes all playbook checks and submits structured results with `verification.checks`
- **`review(approve)`** — QA agent confirms findings are evidence-based, classifications are justified, and no checks were skipped
- **`review(request_changes)`** — QA agent finds incomplete coverage or unjustified classifications

---

## Contracts and Policies

### Agent Contract — Security Audit Context

**Boundaries by task kind:**

| Kind | Role in Audit | Read | Write |
|---|---|---|---|
| `spec` | Reconnaissance (Phase 1) | `.roadmap/**`, `docs/**` | `reports/phase1/**` |
| `impl` | Audit execution (Phase 2) | `.roadmap/**`, `playbooks/**`, `reports/phase1/**` | `reports/phase2/**` |
| `qa` | Classification + report (Phase 3–4) | `.roadmap/**`, `reports/**` | `reports/phase3/**`, `reports/phase4/**`, `reports/final/**` |

### Runtime Policy

| Parameter | Value | Rationale |
|---|---|---|
| Attempt TTL | PT30M | Some domains (infrastructure, data security) require deep analysis |
| Max attempts per task | 3 | Prevents infinite loops on ambiguous codebases |
| Cooldown between attempts | PT2M | Allows context reset between retries |
| Auto-escalation | 3× medium → high | Repeated pattern = systemic issue, not isolated finding |

### Issue Escalation

| Severity | Action | Example in audit context |
|---|---|---|
| `low` | Log only | Missing `Referrer-Policy` header |
| `medium` | Log and flag | CORS with wildcard on non-credentialed endpoints |
| `high` | Block task + notify | SQL injection in authentication controller |
| `critical` | Halt pipeline + notify | Private keys committed to repository |

### Guardrails

Security-specific guardrails enforce audit quality:

- **Never invent vulnerabilities that don't exist** — every finding requires evidence (file, line, command output)
- **Always justify risk technically** — severity must be defended, not assumed
- **Distinguish real risk from improvement** — "missing WAF" on an internal tool is INFO, not HIGH
- **Avoid alarmism without evidence** — false positives erode trust in the audit
- **Classify severity consistently** — CRITICAL/HIGH/MEDIUM/LOW/INFO with objective criteria

---

## Verification Protocol

ESAA-Security inherits the full [ESAA verification protocol](https://arxiv.org/abs/2602.23193). The event store is the source of truth; the read-model is a deterministic projection verified through replay and SHA-256 hashing. The agent or operator can verify integrity at any point by replaying the event log and comparing the computed hash against the stored projection hash:

```python
def esaa_verify(events, roadmap_json):
    projected = project_events(events)          # pure function — no I/O
    hash_input = {
        "schema_version": projected["meta"]["schema_version"],
        "project": projected["project"],
        "tasks": projected["tasks"],
        "indexes": projected["indexes"]
    }
    canonical = json.dumps(hash_input, sort_keys=True, separators=(',', ':')) + '\n'
    computed = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    stored = roadmap_json["meta"]["run"]["projection_hash_sha256"]
    if computed == stored:
        return {"verify_status": "ok"}
    else:
        return {"verify_status": "mismatch"}
```

**What verification means for security audits:**

| Status | Meaning | Orchestrator response |
|---|---|---|
| `ok` | Audit state is consistent — all findings are traceable to events | Continue |
| `mismatch` | Audit state diverges from event log — findings may have been tampered | `reproject_or_halt` |
| `corrupted` | Event store is malformed — audit integrity compromised | `halt_and_snapshot` |

This guarantees that the **final report is a faithful projection of the audit trail** — no findings can be added, removed, or reclassified without leaving a trace in the event store.

---

## Orchestration Cycle

The orchestration cycle follows the ESAA transactional pipeline, specialized here for security audit dispatch:

```
1.  parse_event_store → project current audit state
2.  select_next_eligible_task (depends_on all done; status=todo)
    └─ if none eligible and all done → emit run.end(success) → compile final report
    └─ if deadlock detected → emit issue.report(severity=high)
3.  dispatch_agent → inject: playbook + reconnaissance outputs + roadmap subset
    └─ start TTL timer (PT30M)
4.  validate_agent_output (7-layer, fail-closed)
    ├─ on reject → emit output.rejected → increment attempt_count
    │              └─ if attempt_count >= 3 → emit issue.report(severity=high)
    └─ on accept:
5.      emit agent action event (claim | complete | review | issue.report)
6.      emit orchestrator.file.write (one per report/result file)
7.      emit orchestrator.view.mutate (roadmap.json update)
8.      project_views → rebuild roadmap.json, issues.json
9.      verify_projection → replay + SHA-256
        ├─ verify.ok  → continue to next eligible task
        └─ verify.fail → reproject_or_halt | halt_and_snapshot
10. emit run.end (success | failed | halted)
```

---

## Input Contract

To execute an audit, the agent needs access to the target system. The global input contract defines:

| Input | Required | Description |
|---|---|---|
| `repo_path` | **yes** | Absolute path to the repository under audit |
| `endpoint_base_url` | no | Live application URL for hybrid checks (headers, CORS, rate limiting) |
| `docs_path` | no | Path to technical documentation or architecture docs |
| `infra_config_path` | no | Path to infrastructure configs (docker-compose, k8s, terraform) |
| `ci_config_path` | no | Path to CI/CD configs (.github/workflows, .gitlab-ci.yml) |

Each playbook declares which inputs it requires. The orchestrator validates availability before dispatching.

---

## Security Score

The final report includes a security score (0-100) derived from check results:

| Range | Classification |
|---|---|
| 0–30 | **Critical** — Severe vulnerabilities requiring immediate action |
| 31–50 | **Poor** — Significant security gaps across multiple domains |
| 51–70 | **Fair** — Baseline controls present but notable weaknesses remain |
| 71–85 | **Good** — Solid security posture with room for hardening |
| 86–100 | **Excellent** — Comprehensive controls across all audited domains |

The score is computed from individual check results weighted by severity, ensuring that a single CRITICAL finding has proportionally more impact than multiple LOW findings.

---

## Audit Level

ESAA-Security is calibrated for **internal audits at L1/L2 maturity**:

| Use Case | Fit |
|---|---|
| Dev/deploy checklist | Functional — simplify by extracting checks without governance |
| Internal audit (L1/L2) | **Sweet spot** — full coverage with ESAA traceability |
| Regulatory compliance (LGPD) | Technical component — complement with process documentation |
| Formal certification (ISO 27001, PCI-DSS) | Insufficient standalone — needs organizational controls and formal methodology |

The 16 domains map well to OWASP Top 10, ASVS Level 1, and partially Level 2. The AI/LLM Security domain (AI-001 → AI-005) extends coverage to a category most traditional frameworks don't address.

---

## Getting Started

### Prerequisites

- At least one authenticated agent CLI installed locally:
  - [Codex](https://github.com/openai/codex) (OpenAI)
  - [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (Anthropic)
  - [Gemini CLI](https://github.com/google-gemini/gemini-cli) (Google)
- Access to the target repository to be audited

### Run an Audit

ESAA-Security does not require a dedicated CLI. The audit is executed by an LLM agent (Codex, Claude Code, or Gemini CLI) operating inside the project directory. The agent reads the initialization file, follows the ESAA workflow contracts, and executes tasks sequentially through the `claim → complete → review` cycle.

1. Clone the repository and set up the target:
   ```bash
   git clone https://github.com/elzobrito/esaa-security.git
   cd esaa-security
   ```

2. Configure the target repository in `.roadmap/init.yaml`:
   ```yaml
   # .roadmap/init.yaml — point to the repository under audit
   repo_path: /path/to/target/repo
   # Optional: live endpoint for hybrid checks (headers, CORS, rate limiting)
   endpoint_base_url: http://localhost:3000
   ```

3. Open the project in your agent CLI and instruct it to begin:
   ```bash
   # Example with Codex
   codex

   # Example with Claude Code
   claude

   # Example with Gemini CLI
   gemini
   ```

   Then instruct the agent:
   ```
   Read .roadmap/init.yaml and begin executing the audit roadmap.
   Follow the ESAA workflow: claim each task before working,
   complete with structured results and verification evidence.
   ```

   The agent will:
   - Read `init.yaml` for project configuration and target path
   - Read `roadmap.json` to identify eligible tasks (status `todo`, dependencies satisfied)
   - Claim the next eligible task
   - Execute the corresponding playbook from `playbooks/playbooks.security.json`
   - Emit structured results (check status, severity, evidence, remediation)
   - Complete the task with verification checks
   - Proceed to the next eligible task until all phases are done

4. Monitor progress:
   ```bash
   cat .roadmap/roadmap.json      # Current audit state — tasks, statuses, indexes
   cat .roadmap/activity.jsonl    # Append-only event log — every claim, completion, finding
   ```

5. Read the final report (generated in Phase 4):
   ```bash
   cat reports/final/security-audit-report.md
   cat reports/phase4/executive-summary.md    # 1-page summary with security score
   cat reports/phase4/technical-remediations.md
   cat reports/phase4/best-practices.md
   ```

---

## Artifacts

| Artifact | Schema | Description |
|---|---|---|
| `roadmap.security.json` | ESAA v0.4.0 | Audit roadmap — 26 tasks, 4 phases, schema-validated |
| `playbooks.security.json` | playbooks.security.v1 | 95 executable checks across 16 domains with agent instructions |
| `PARCER_v1.6.0-security-audit.yaml` | — | Source framework defining security domains, guardrails, and agent governance ([paper](https://arxiv.org/abs/2603.00856)) |

---

## Comparison with Existing Approaches

| Feature | Ad-hoc LLM review | OWASP Checklist | Commercial scanner | ESAA-Security |
|---|---|---|---|---|
| Structured coverage | ✗ | ✓ | ✓ | ✓ (95 checks, 16 domains) |
| Agent-executable | ✗ | ✗ | ✗ | ✓ (playbooks with concrete commands) |
| Audit trail | ✗ | ✗ | Partial | ✓ (append-only event store) |
| Deterministic replay | ✗ | ✗ | ✗ | ✓ (SHA-256 verified) |
| AI/LLM domain coverage | ✗ | ✗ | ✗ | ✓ (5 checks) |
| LGPD-aware | ✗ | ✗ | Partial | ✓ (DA-005) |
| Open framework | ✗ | ✓ | ✗ | ✓ |

---

## Case Study: ESAA-Supervisor — Vibe Coding Under Audit

ESAA-Security was validated against the [ESAA-Supervisor](https://github.com/elzobrito/esaa-supervisor), a full-stack web application for AI agent supervision built entirely through vibe coding with five frontier LLMs: **GPT 5.4**, **GPT 5.3-codex** (OpenAI Codex), **Claude Opus 4.6**, **Claude Sonnet 4.5** (Anthropic), and **Gemini 3.1 Pro** (Google DeepMind). The system comprises a FastAPI backend, a React/TypeScript frontend, multi-agent CLI orchestration, SSE log streaming, filesystem-backed canonical state, persistent chat, and token telemetry. All 18 roadmap tasks were completed — functionally, the system worked.

The ESAA-Security audit pipeline executed all four phases — reconnaissance, domain audit execution across 16 domains, risk classification, and final reporting — producing structured check results, a vulnerability inventory, a risk matrix, technical remediations, best-practice guidance, and an executive summary.

### Audit Results

| Metric | Value |
|---|---|
| **Security Score** | **19.5 / 100 — CRITICAL** |
| CRITICAL vulnerabilities | 9 |
| HIGH vulnerabilities | 15 |
| Total vulnerabilities | 24 |
| Domains affected | 12 / 16 |
| Estimated remediation effort | ~61.5 hours across 3 sprints |

### Score Breakdown by Domain

| Domain | Score | Classification |
|---|---|---|
| Dependencies & Supply Chain | 92.3% | Good |
| Frontend Security | 80.0% | Good |
| Cryptography | 37.5% | Insufficient |
| Secrets & Configuration | 36.4% | Insufficient |
| AI/LLM Security | 5.3% | Critical |
| Authentication / Authorization | 0.0% | Nonexistent |

### Top 5 Critical Findings

| ID | Vulnerability | Severity | Impact |
|---|---|---|---|
| AZ-001 | Access control absent — API fully open, any network actor can execute agents, modify state, read host files | CRITICAL | Total |
| AI-001 | Prompt injection — chat messages sent directly to LLM without delimiters, escaping, or injection filters | CRITICAL | High |
| AZ-002 | IDOR / Path Traversal — `/browse` endpoint allows arbitrary filesystem navigation on the host | CRITICAL | Medium |
| SC-004 | Permissive CORS (`*`) — any website can make authenticated requests to the API | CRITICAL | Medium |
| AI-002 | LLM with unrestricted access — `--approval-mode yolo` and `--permission-mode bypassPermissions` enable execution without human approval | CRITICAL | High |

### Key Observations

The audit revealed a systematic pattern: all five models excelled at generating functionally correct code with clean dependencies and reasonable frontend security, but **none implemented security controls proactively**. Authentication, authorization, input sanitization, rate limiting, session management, RBAC, and CSP headers were entirely absent — not because they were explicitly excluded, but because they were never requested.

The models consistently chose the **path of least friction**: `CORS: *`, `--approval-mode yolo`, `bypassPermissions` — configurations that make code work on the first attempt but create critical attack surfaces. Security is a cross-cutting architectural concern that requires deliberate design decisions; vibe coding systematically eliminates the friction where those decisions would normally occur.

The global score was penalized (Cap 50) due to more than 3 unmitigated CRITICAL vulnerabilities in core domains, reflecting real-world methodology: frontend quality is irrelevant when the API is completely open.

### Remediation Roadmap

The technical remediations document organizes fixes into three sprints:

| Sprint | Focus | Effort | Key Fixes |
|---|---|---|---|
| Sprint 1 | Production blockers | ~14h | CORS restriction, auth middleware, path sandboxing, bypass mode removal |
| Sprint 2 | Operational security | ~17h | Log redaction, rate limiting, prompt injection defense, RBAC, security headers |
| Sprint 3 | Full hardening | ~25h | bcrypt + JWT, HTTPS/TLS, output sanitization, upload validation, LGPD retention policy |

All findings were mapped against **OWASP Top 10:2021**, **OWASP ASVS 5.0**, **CIS Controls v8.1**, **NIST CSF 2.0**, and **NIST SP 800-53 Rev. 5**.

> **Blog post:** [19.5/100 — O Custo Real do Vibe Coding](reports/blogpost/vibecoding-security-blogpost.html) — a detailed narrative exploring why LLMs produce insecure code by default and what practitioners should do about it.

---

## Roadmap

- [x] **First case study** — ESAA-Supervisor audit: 19.5/100, 24 vulnerabilities, full artifact chain produced
- [x] **arXiv publication** — [arXiv:2603.06365](https://arxiv.org/abs/2603.06365)
- [ ] **Assessment mode** — Flat checklist for third-party self-assessment (derived from playbooks)
- [ ] **CVSS scoring integration** — Map findings to CVSS v4.0 for standardized severity
- [ ] **Live DAST integration** — OWASP ZAP / Nuclei execution as hybrid check strategy
- [ ] **Multi-repo audit** — Orchestrate audits across microservice repositories
- [ ] **Compliance mapping** — Automated mapping of checks to LGPD articles, OWASP ASVS, CIS Controls
- [ ] **Temporal comparison** — Diff security posture between audit runs

---

## Citation

If you use ESAA-Security in your research, please cite:

```bibtex
@article{santos2026esaasecurity,
  title={ESAA-Security: An Event-Sourced, Verifiable Architecture for Agent-Assisted Security Audits of AI-Generated Code},
  author={Brito dos Santos Filho, Elzo},
  journal={arXiv preprint arXiv:2603.06365},
  year={2026},
  url={https://arxiv.org/abs/2603.06365}
}
```

For the underlying ESAA architecture:

```bibtex
@article{santos2026esaa,
  title={ESAA: Event Sourcing for Autonomous Agents in LLM-Based Software Engineering},
  author={Brito dos Santos Filho, Elzo},
  journal={arXiv preprint arXiv:2602.23193},
  year={2026},
  url={https://arxiv.org/abs/2602.23193}
}
```

For the PARCER operational contract framework:

```bibtex
@article{santos2026parcer,
  title={PARCER as an Operational Contract to Reduce Variance, Cost, and Risk in LLM Systems},
  author={Brito dos Santos Filho, Elzo},
  journal={arXiv preprint arXiv:2603.00856},
  year={2026},
  url={https://arxiv.org/abs/2603.00856}
}
```

---

## License

MIT

---

## Author

**Elzo Brito dos Santos Filho**
📧 elzo.santos@cps.sp.gov.br
