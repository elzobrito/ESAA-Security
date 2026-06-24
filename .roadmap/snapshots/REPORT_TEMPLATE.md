# ESAA Security Audit Report

> **Relatório gerado automaticamente por agentes ESAA-Security.**
> Cada achado é rastreável ao event store via `projection_hash_sha256`.

---

## Informações do Relatório

| Campo | Valor |
|---|---|
| **Report ID** | `${header.report_id}` |
| **Data de Geração** | `${header.generated_at}` |
| **Run ID** | `${header.run_id}` |
| **Projection Hash** | `${header.projection_hash_sha256}` |
| **Escopo** | ${header.audit_scope} |
| **Repositório** | `${header.target.repo_path}` |
| **Endpoint Testado** | `${header.target.endpoint_base_url}` |
| **Stack** | ${header.target.tech_stack_summary} |

---

## 1. Resumo Executivo

### Score de Segurança

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              SECURITY SCORE: ${score.value}/100            ║
║              Classificação: ${score.classification}        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

| Métrica | Valor |
|---|---|
| Checks executados | ${stats.total_checks_executed} |
| Aprovados | ${stats.checks_pass} |
| Reprovados | ${stats.checks_fail} |
| Parciais | ${stats.checks_partial} |
| Não aplicáveis | ${stats.checks_na} |
| Domínios auditados | ${stats.domains_audited} |

| Severidade | Findings |
|---|---|
| CRITICAL | ${stats.critical_findings} |
| HIGH | ${stats.high_findings} |
| MEDIUM | ${stats.medium_findings} |
| LOW | ${stats.low_findings} |
| INFO | ${stats.info_findings} |

### Avaliação Geral

${executive_summary.overall_assessment}

### Score por Domínio

<!-- Ordenado por score ascendente (piores primeiro) -->

| Domínio | Score | Pass | Fail | N/A | Prioridade |
|---|---|---|---|---|---|
| ${domain.domain_title} | ${domain.score}/100 | ${domain.checks_pass} | ${domain.checks_fail} | ${domain.checks_na} | ${domain.priority} |
| ... | ... | ... | ... | ... | ... |

### Top 5 Riscos Prioritários

| # | Vulnerabilidade | Domínio | Severidade | Ação Imediata |
|---|---|---|---|---|
| 1 | ${top_risks[0].vulnerability} | ${top_risks[0].domain} | ${top_risks[0].severity} | ${top_risks[0].immediate_action} |
| 2 | ${top_risks[1].vulnerability} | ${top_risks[1].domain} | ${top_risks[1].severity} | ${top_risks[1].immediate_action} |
| 3 | ${top_risks[2].vulnerability} | ${top_risks[2].domain} | ${top_risks[2].severity} | ${top_risks[2].immediate_action} |
| 4 | ${top_risks[3].vulnerability} | ${top_risks[3].domain} | ${top_risks[3].severity} | ${top_risks[3].immediate_action} |
| 5 | ${top_risks[4].vulnerability} | ${top_risks[4].domain} | ${top_risks[4].severity} | ${top_risks[4].immediate_action} |

---

## 2. Matriz de Vulnerabilidades

<!-- Todas as vulnerabilidades encontradas, ordenadas por severidade decrescente -->
<!-- Apenas checks com status fail ou partial entram aqui -->

| Finding | Check | Vulnerabilidade | Domínio | Severidade | C | I | D | Status | Correção |
|---|---|---|---|---|---|---|---|---|---|
| ${finding_id} | ${check_id} | ${vulnerability} | ${domain} | ${severity} | ${impact_cia.confidentiality} | ${impact_cia.integrity} | ${impact_cia.availability} | ${status} | ${remediation_summary} |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |

> **Legenda CIA:** C = Confidencialidade, I = Integridade, D = Disponibilidade. Valores: none / low / medium / high.

---

## 3. Análise Detalhada por Categoria

<!-- Uma seção por domínio auditado. Domínios ordenados por prioridade (critical → high → medium) -->

### 3.${N}. ${domain_title}

**Prioridade:** ${domain_priority} | **Score:** ${domain_score}/100 | **Checks:** ${pass} pass, ${fail} fail, ${partial} partial, ${na} n/a

${domain_summary}

#### ${check_id}: ${check_name}

**Status:** ${status} | **Severidade se fail:** ${severity_if_fail}

<!-- Se status = fail ou partial: -->

**Evidência:**

- **Arquivos:** ${evidence.files}
- **Linhas:** `${evidence.lines}`
- **Comandos executados:**
  ```
  ${evidence.commands_output}
  ```
- **Descrição:** ${evidence.description}

**Correção recomendada:**

${remediation}

**Referências:** ${references}

---

<!-- Se status = pass: -->

**Resultado:** Check aprovado. ${pass_description_if_relevant}

---

<!-- Repetir para cada check do domínio -->
<!-- Repetir para cada domínio -->

---

## 4. Riscos Prioritários

<!-- Expansão narrativa dos top 5 riscos do resumo executivo -->

### Risco #${rank}: ${title}

**Finding:** ${finding_id} | **Severidade:** ${severity} | **Esforço estimado:** ${effort_estimate}

#### Análise de Impacto

${impact_analysis}

#### Cenário de Exploração

${exploitation_scenario}

#### Roadmap de Correção

| Prazo | Ação |
|---|---|
| **Imediato (24h)** | ${remediation_roadmap.immediate} |
| **Curto prazo (1-2 semanas)** | ${remediation_roadmap.short_term} |
| **Longo prazo (permanente)** | ${remediation_roadmap.long_term} |

---

<!-- Repetir para cada risco prioritário -->

---

## 5. Recomendações Técnicas

### Tier 1 — Ação Imediata (48h)

<!-- Correções para findings CRITICAL -->

**${finding_id}: ${action}**

```
${code_snippet}
```

Verificação: `${verification_command}`

---

<!-- Repetir para cada correção Tier 1 -->

### Tier 2 — Curto Prazo (2 semanas)

<!-- Correções para findings HIGH -->

**${finding_id}: ${action}**

```
${code_snippet}
```

Verificação: `${verification_command}`

---

<!-- Repetir para cada correção Tier 2 -->

### Tier 3 — Hardening (próximo ciclo)

<!-- Correções para findings MEDIUM e LOW -->

| Finding | Ação |
|---|---|
| ${finding_id} | ${action} |
| ... | ... |

### Tier 4 — Boas Práticas

<!-- Recomendações preventivas por domínio -->

| Domínio | Prática | Referência |
|---|---|---|
| ${domain} | ${practice} | ${reference} |
| ... | ... | ... |

---

## Apêndice A — Resultados Completos

<!-- Tabela de todos os 108 checks, incluindo pass e not_applicable -->

| Check | Domínio | Nome | Status | Severidade |
|---|---|---|---|---|
| ${check_id} | ${domain} | ${check_name} | ${status} | ${severity_if_fail} |
| ... | ... | ... | ... | ... |

---

## Apêndice B — Cobertura por Domínio

| Domínio | Total | Executados | N/A | Cobertura |
|---|---|---|---|---|
| ${domain} | ${total_checks} | ${executed} | ${not_applicable} | ${coverage_pct}% |
| ... | ... | ... | ... | ... |

### Justificativas de Não Aplicabilidade

<!-- Apenas checks marcados como not_applicable com justificativa -->

| Check | Domínio | Motivo |
|---|---|---|
| ${check_id} | ${domain} | ${reason} |
| ... | ... | ... |

---

## Apêndice C — Metadados da Auditoria

| Campo | Valor |
|---|---|
| Run ID | `${audit_metadata.run_id}` |
| Projection Hash SHA-256 | `${audit_metadata.projection_hash_sha256}` |
| Total de eventos | ${audit_metadata.total_events} |
| Início da auditoria | ${audit_metadata.audit_start} |
| Fim da auditoria | ${audit_metadata.audit_end} |
| Modelo do agente | ${audit_metadata.agent_model} |
| Versão dos playbooks | ${audit_metadata.playbooks_version} |
| Schema do roadmap | ${audit_metadata.roadmap_schema_version} |

---

## Apêndice D — Fórmula do Score

O score de segurança é calculado de forma determinística:

### Pesos por Severidade

| Severidade | Peso |
|---|---|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 2 |
| INFO | 1 |

### Pontuação por Status

| Status | Pontuação |
|---|---|
| pass | peso total |
| partial | peso × 0.5 |
| fail | 0 |
| not_applicable | excluído do cálculo |
| error | 0 |

### Score por Domínio

```
domain_score = (Σ pontos dos checks / Σ pesos máximos dos checks aplicáveis) × 100
```

### Score Global

```
global_score = Σ(domain_score × domain_weight) / Σ(domain_weights)
```

Pesos por prioridade de domínio: critical = 3.0, high = 2.0, medium = 1.0.

### Penalidades

| Condição | Penalidade |
|---|---|
| Qualquer finding CRITICAL sem mitigação | Score capped em 70 |
| 3+ findings CRITICAL | Score capped em 50 |
| Qualquer domínio critical com score 0 | Score capped em 60 |

---

> **Nota de integridade:** Este relatório é uma projeção determinística do event store ESAA.
> Para verificar a integridade, execute `esaa verify --strict` e compare o
> `projection_hash_sha256` com o valor registrado no cabeçalho deste relatório.
> Mesmos eventos sempre produzem o mesmo relatório.