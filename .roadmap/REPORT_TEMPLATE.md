<!--
ESAA Security Audit Report — Markdown Render Template
=====================================================
Esqueleto de renderização consumido por SEC-043. O agente projeta os dados de
reports/phase2/results/SEC-*.json e reports/phase3/*.json neste formato.
Regras de renderização:
  - Tokens {{...}} são substituídos por valores escalares.
  - Blocos {{#each X}} ... {{/each}} repetem por item da coleção X.
  - Blocos {{#if X}} ... {{/if}} são incluídos apenas quando X é verdadeiro/não-vazio.
  - Schema de dados de origem: .roadmap/report-template.security.json (report_schema).
  - Output determinístico: mesmos result files => mesmo relatório.
  - NÃO editar o .md final à mão — regenerar via este template.
-->

# Relatório de Auditoria de Segurança — {{header.target.repo_path}}

| Campo | Valor |
|-------|-------|
| Report ID | {{header.report_id}} |
| Gerado em | {{header.generated_at}} |
| Run ID | {{header.run_id}} |
| Projection hash (SHA-256) | `{{header.projection_hash_sha256}}` |
| Escopo da auditoria | {{header.audit_scope}} |
| Repositório | `{{header.target.repo_path}}` |
| Endpoint runtime | {{header.target.endpoint_base_url}} |
| Stack | {{header.target.tech_stack_summary}} |

---

## 1. Resumo Executivo

{{executive_summary.overall_assessment}}

### Security Score

> **{{executive_summary.security_score.value}} / 100 — {{executive_summary.security_score.classification}}**

**Score por domínio**

| Domínio | Score | Pass | Fail | N/A |
|---------|------:|-----:|-----:|----:|
{{#each executive_summary.security_score.breakdown}}
| {{domain}} | {{score}} | {{checks_pass}} | {{checks_fail}} | {{checks_na}} |
{{/each}}

### Estatísticas

| Métrica | Valor |
|---------|------:|
| Checks executados | {{executive_summary.stats.total_checks_executed}} |
| Pass | {{executive_summary.stats.checks_pass}} |
| Fail | {{executive_summary.stats.checks_fail}} |
| Partial | {{executive_summary.stats.checks_partial}} |
| Not applicable | {{executive_summary.stats.checks_na}} |
| Domínios auditados | {{executive_summary.stats.domains_audited}} |
| CRITICAL | {{executive_summary.stats.critical_findings}} |
| HIGH | {{executive_summary.stats.high_findings}} |
| MEDIUM | {{executive_summary.stats.medium_findings}} |
| LOW | {{executive_summary.stats.low_findings}} |
| INFO | {{executive_summary.stats.info_findings}} |

### Top 5 Riscos

| # | Check | Vulnerabilidade | Domínio | Severidade | Ação imediata |
|--:|-------|-----------------|---------|------------|---------------|
{{#each executive_summary.top_risks}}
| {{rank}} | {{check_id}} | {{vulnerability}} | {{domain}} | {{severity}} | {{immediate_action}} |
{{/each}}

---

## 2. Matriz de Vulnerabilidades

Todas as vulnerabilidades (status `fail`/`partial`), ordenadas por severidade decrescente.

| Finding | Check | Vulnerabilidade | Domínio | Severidade | Impacto C/I/A | Status | Remediação |
|---------|-------|-----------------|---------|------------|---------------|--------|------------|
{{#each vulnerability_matrix}}
| {{finding_id}} | {{check_id}} | {{vulnerability}} | {{domain}} | {{severity}} | {{impact_cia.confidentiality}}/{{impact_cia.integrity}}/{{impact_cia.availability}} | {{status}} | {{remediation_summary}} |
{{/each}}

---

## 3. Análise Detalhada por Domínio

{{#each detailed_analysis.per_domain}}
### {{domain_title}} (`{{domain_key}}`)

- **Prioridade:** {{domain_priority}}
- **Score do domínio:** {{domain_score}} / 100

{{summary}}

{{#each checks}}
#### {{check_id}} — {{check_name}}

- **Status:** {{status}}{{#if severity_if_fail}} · **Severidade:** {{severity_if_fail}}{{/if}}
- **Evidência:** {{evidence.description}}
{{#if evidence.files}}
- **Arquivos:** {{evidence.files}}
{{/if}}
{{#if evidence.lines}}
- **Linhas/trechos:** {{evidence.lines}}
{{/if}}
{{#if evidence.commands_output}}
- **Saída de comandos:** {{evidence.commands_output}}
{{/if}}
{{#if remediation}}
- **Remediação:** {{remediation}}
{{/if}}
{{#if references}}
- **Referências:** {{references}}
{{/if}}

{{/each}}
{{/each}}

---

## 4. Riscos Prioritários (análise expandida)

{{#each priority_risks}}
### #{{rank}} — {{title}} ({{finding_id}}) · {{severity}}

**Impacto:** {{impact_analysis}}

**Cenário de exploração:** {{exploitation_scenario}}

**Roadmap de correção**

- **Imediato (24h):** {{remediation_roadmap.immediate}}
- **Curto prazo (1-2 semanas):** {{remediation_roadmap.short_term}}
- **Longo prazo:** {{remediation_roadmap.long_term}}

**Esforço estimado:** {{effort_estimate}}

{{/each}}

---

## 5. Recomendações Técnicas

### Tier 1 — Imediato (CRITICAL, ≤48h)

{{#each technical_recommendations.tiers.tier_1_immediate.items}}
- **{{finding_id}}:** {{action}}
{{#if code_snippet}}
  ```
  {{code_snippet}}
  ```
{{/if}}
  - Verificação: `{{verification_command}}`
{{/each}}

### Tier 2 — Curto prazo (HIGH, ≤2 semanas)

{{#each technical_recommendations.tiers.tier_2_short_term.items}}
- **{{finding_id}}:** {{action}}
{{#if code_snippet}}
  ```
  {{code_snippet}}
  ```
{{/if}}
  - Verificação: `{{verification_command}}`
{{/each}}

### Tier 3 — Hardening (MEDIUM/LOW, próximo ciclo)

{{#each technical_recommendations.tiers.tier_3_hardening.items}}
- **{{finding_id}}:** {{action}}
{{/each}}

### Tier 4 — Boas práticas

{{#each technical_recommendations.tiers.tier_4_best_practices.items}}
- **[{{domain}}]** {{practice}} — {{reference}}
{{/each}}

---

## 6. Apêndice

### 6.1 Resultado completo dos checks

| Check | Domínio | Nome | Status | Severidade (se fail) |
|-------|---------|------|--------|----------------------|
{{#each appendix.full_check_results}}
| {{check_id}} | {{domain}} | {{check_name}} | {{status}} | {{severity_if_fail}} |
{{/each}}

### 6.2 Metadados da auditoria

| Campo | Valor |
|-------|-------|
| Run ID | {{appendix.audit_metadata.run_id}} |
| Projection hash | `{{appendix.audit_metadata.projection_hash_sha256}}` |
| Total de eventos | {{appendix.audit_metadata.total_events}} |
| Início | {{appendix.audit_metadata.audit_start}} |
| Fim | {{appendix.audit_metadata.audit_end}} |
| Modelo do agente | {{appendix.audit_metadata.agent_model}} |
| Versão dos playbooks | {{appendix.audit_metadata.playbooks_version}} |
| Schema do roadmap | {{appendix.audit_metadata.roadmap_schema_version}} |

### 6.3 Cobertura por domínio

| Domínio | Total checks | Executados | N/A |
|---------|-------------:|-----------:|----:|
{{#each appendix.domain_coverage.per_domain}}
| {{domain}} | {{total_checks}} | {{executed}} | {{not_applicable}} |
{{/each}}

{{#each appendix.domain_coverage.per_domain}}
{{#if na_justifications}}
**Justificativas de N/A — {{domain}}**
{{#each na_justifications}}
- `{{check_id}}`: {{reason}}
{{/each}}
{{/if}}
{{/each}}

---

*Relatório gerado deterministicamente pelo ESAA (SEC-043) a partir do event store `.roadmap/activity.jsonl`. Score conforme `score_calculation` de `.roadmap/report-template.security.json`. Rastreável via `finding_id` → `check_id` → result file de fase 2.*
