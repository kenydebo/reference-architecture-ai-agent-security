# Threat model

Scope: an enterprise AI agent with brokered access to internal systems holding
research data, documents, manufacturing records and ERP data. The environment
is fictional and all data is synthetic.

See [`architecture.md`](architecture.md) for trust boundaries and the full
control mapping.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Restricted / PHI-classified records | Regulatory exposure, harm to individuals |
| Research and manufacturing IP | Core enterprise value |
| Enterprise tool access (export, write actions) | Agent-mediated actions have real side effects |
| The security evidence record | If forgeable, every downstream assertion collapses |

## 2. Threat actors

- **External attacker via indirect prompt injection** - plants instructions in
  content the agent will retrieve.
- **Compromised or malfunctioning agent** - attempts actions beyond its purpose.
- **Careless insider / misconfiguration** - provisions an over-broad credential
  scope.
- **Insider attempting to alter the record** - edits or removes evidence after
  an incident.

## 3. STRIDE-aligned analysis

| # | Category | Threat | Control | Demonstrated in |
|---|---|---|---|---|
| T1 | Tampering (input) | Injected instructions in retrieved content | Capability limits independent of content; indicators recorded per document | Scenario 2 |
| T2 | Elevation of privilege | Hijacked agent requests a restricted tool | Default-deny ABAC; scope + classification + role grant | Scenario 2 |
| T3 | Information disclosure | Export of restricted / PHI data | `AI-DATA-004` classification rule; output screening | Scenarios 2, 3 |
| T4 | Spoofing | Credential replayed into another session | Session binding; short TTL | `demo.py`, `tests/test_identity.py` |
| T5 | Elevation via misconfiguration | Over-broad credential scope | Classification rule denies independently of scope | Scenario 3 |
| T6 | Tampering (record) | Edit, delete, reorder or re-sign evidence | Hash chain + Ed25519 + independent trust anchor | `tests/test_forensics.py` |
| T7 | Repudiation | "That action never happened" | Signed, ordered, correlated evidence | Scenario 4 |
| T8 | Anti-forensics | "Do not disclose this action" in injected text | Recording is control-plane side; the instruction itself is flagged | Scenario 2 |
| T9 | Information disclosure (audit) | Sensitive values copied into the audit record | Findings record category and value hash, never the value | `tests/test_controls.py` |

## 4. Attack path walked in scenario 2

```
attacker plants instruction in a vendor document
        |
        v
agent retrieves it as untrusted context     -> rag.document_retrieved
        |                                      detection.injection_indicator
        v
planner obeys, requests clinical_data.export -> agent.tool_requested
        |
        v
tool broker validates the credential          -> identity.validation_succeeded
        |
        v
authorization evaluates the request           -> policy.decision  DENY
   AI-DATA-004    classification: restricted_phi for research_reader
   AI-IAM-004     least privilege: outside credential scope
   AI-DEFAULT-DENY no role grant for this action
        |
        v
execution refused                             -> tool.execution_denied
        |
        v
incident raised, severity HIGH                -> security.incident_created
```

Detection contributed the severity and the pointer to the source document. It
did not contribute the containment.

## 5. What is explicitly out of scope

- **Semantic correctness of an authorized action.** A validly authorized but
  wrong action is not caught here; that belongs to workflow-level approval.
- **Model behaviour.** No claim is made about whether a real model would obey
  this injection, or at what rate. No model is called.
- **Retrieval ranking.** The corpus is read whole; retrieval relevance is not
  modelled.
- **A compromised control plane.** See the limitations section of
  `architecture.md`.
- **Denial of service** against the gateway or the backing systems.
