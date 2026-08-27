# AI Agent Security Reference Architecture

**Keny - personal engineering project**

A working reference implementation demonstrating how I approach securing
enterprise AI agents that interact with sensitive data and internal tools.

The architecture focuses on:

- workload identity for agents
- short-lived, session-bound, scope-limited credentials
- least-privilege tool access through a broker
- default-deny authorization
- data-classification enforcement
- indirect prompt-injection detection
- security telemetry
- incident reconstruction
- evidence-based control validation

> This project uses synthetic data and a fictional biotechnology environment.
> It does not represent or reproduce any organization's internal AI
> architecture. No real data of any kind is included.

---

## The security problem

Enterprise AI agents increasingly hold access to internal data and operational
tooling: research databases, document repositories, quality systems, ERP. When
an agent is compromised - most commonly through **indirect prompt injection**,
where instructions are planted in content the agent retrieves - the result is
not a bad model answer. It is an **authorization and enterprise-security
problem**, because the agent is already authenticated and already reachable to
the systems it can call.

```
Prompt Injection
       |
       v
Compromised Agent
       |
       v
Unauthorized Tool Request
       |
       v
+--------------------------------+
|      AI SECURITY GATEWAY       |
|                                |
|  Identity                      |
|  Authorization                 |
|  Tool Broker                   |
|  Data Classification           |
|  Detection                     |
|  Security Telemetry            |
+--------------------------------+
       |
       v
      DENY
```

The core principle:

> **The agent is not trusted simply because it generated the request.**

The important design decision is that **containment does not depend on
successfully identifying every malicious prompt**. The agent's capabilities are
constrained at the execution boundary. Detection assists investigation and
triage; authorization provides containment.

---

## Quick start

```bash
git clone https://github.com/kenydebo/keny-ai-agent-security-reference-architecture.git
cd keny-ai-agent-security-reference-architecture

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python demo.py
```

To run the tests:

```bash
pip install -r requirements-dev.txt
pytest
```

No API key, no network access, and no model call is required.

---

## Scenarios

Each scenario runs standalone and is reproducible.

```bash
python -m scenarios.normal_request         # authorized work still functions
python -m scenarios.prompt_injection       # injection detected, action denied
python -m scenarios.overprivileged_token   # defense in depth
python -m scenarios.investigate_incident   # reconstruction + control validation
```

### 1. Normal authorized operation

A research agent searches internal research data. Identity is validated, policy
is evaluated, the action is authorized and executes. A second call returns an
excerpt containing a synthetic identifier, which output screening detects and
redacts before it reaches the agent.

### 2. Indirect prompt injection

A retrieved vendor appendix carries an embedded instruction to export a
restricted patient dataset and not to disclose it. The agent obeys and requests
`clinical_data.export`.

Three independent controls deny the request, and **none of them is the
detector**:

| Policy | Control | Why it denied |
|---|---|---|
| `AI-DATA-004` | data classification | `research_reader` may not act on `restricted_phi` |
| `AI-IAM-004` | least privilege | the action is outside the credential's scope |
| `AI-DEFAULT-DENY` | default deny | no policy grants this role this action |

Detection records indicators against the source document and raises the
incident severity to HIGH. Delete the detector entirely and the export is still
denied.

### 3. Misconfigured / overprivileged credential

The research agent is deliberately minted a credential whose scope wrongly
includes `clinical_data.export`. The least-privilege control therefore **does
not** deny - the action is legitimately in scope. The classification rule denies
it anyway.

A single misconfigured identity scope does not produce unrestricted access.

### 4. Investigation and control validation

The incident from scenario 2 is reconstructed from recorded evidence alone -
who initiated the session, which agent and identity acted, which document
carried the instruction, what was requested, which policy decided, whether it
executed, and which incident was raised. Controls are then validated against
that same evidence.

---

## Evidence and control validation

Security decisions are recorded at the moment of enforcement by the gateway,
not by the agent, so a hijacked agent cannot suppress the record of its own
denied request. The ledger is hash-chained and Ed25519-signed.

Control assertions are validated against that evidence rather than asserted.
Each control inspects the evidence **specific to it** - a denial of a
misspelled tool name does not satisfy the restricted-data control:

| Control | Evidence required |
|---|---|
| AC-01 Agent identity required | validated workload identity before any action |
| AC-02 Session-bound credential | credential/session match, or a rejected replay |
| AC-03 Least privilege enforced | no ALLOW outside the credential scope |
| AC-04 Restricted data export prevented | `clinical_data.export` + `restricted_phi` + DENY |
| AC-05 Classification backstop effective | `AI-DATA-004` denied while scope permitted |
| AC-06 Injection detection recorded | indicator linked to a retrieved document |
| AC-07 Incident generated | one incident per enforcement event |
| AC-08 Sensitive output screened | identifiers detected and redacted |
| AC-09 Activity reconstructable | correlated user, identity, action, outcome |
| AC-10 Evidence integrity | verifies against an independent trust anchor |

Results are `PASS`, `FAIL`, or `NOT_TESTED`. **A control that was not exercised
is never reported as passing.** Running a single scenario correctly leaves
several controls `NOT_TESTED`; `demo.py` aggregates all scenarios so every
control is exercised.

---

## What this project demonstrates

- agent workload identity, session binding, and credential rejection
- least-privilege, default-deny authorization over agent-to-tool actions
- blast-radius reduction when an agent is hijacked
- reproducible attack simulation
- security telemetry at the enforcement boundary
- forensic reconstruction derived from recorded events
- control validation derived from evidence rather than asserted

## What this project does not claim

- complete or robust prompt-injection prevention
- production-grade IAM, DLP, or policy infrastructure
- legal admissibility of the evidence it produces
- real-model injection success rates, jailbreak resistance, or RAG ranking
  effectiveness - no model is called
- reproduction of any organization's internal AI architecture
- production scale
- any real clinical, patient, or proprietary data

Known limitations are stated in
[`architecture/architecture.md`](architecture/architecture.md), including the
one that matters most: a backward-linking hash chain cannot detect truncation
of its own tail without an independently retained chain head.

---

## Layout

```
demo.py                     end-to-end run of all four scenarios
architecture/               architecture and threat model
gateway/identity.py         workload identity, session-bound credentials
gateway/authorization.py    ABAC policy engine (executable reference)
gateway/tool_broker.py      the enforcement boundary
gateway/detection.py        injection indicators and output screening
agents/research_agent.py    deterministic agent session
forensics/evidence.py       hash-chained, signed evidence ledger
forensics/reconstruct.py    event-derived incident reconstruction
assurance/controls.py       evidence-based control validation
scenarios/                  four standalone reproducible scenarios
data/synthetic_research/    synthetic corpus including one poisoned document
tests/                      positive and negative cases for every control
```

## Design notes

**The planner is deterministic on purpose.** No model is called and no API key
is required. The security claim is about the enforcement boundary, and that
boundary evaluates a requested action identically whether it originated from a
language model, an attacker-controlled planner, or faulty application logic.

**The Python policy engine is the executable reference.** A production
deployment would run an external policy decision point - OPA, Cedar, or a cloud
IAM policy engine. The evaluation input is shaped as a policy input document so
it maps onto one directly. No external PDP is claimed or shipped here.

**Verification requires a trust anchor.** `verify_ledger()` takes the trusted
public key as a required argument and the ledger never offers its own key. A
verifier that read its key from beside the evidence would accept a wholesale
re-signed history; there is a test for exactly that attack.
