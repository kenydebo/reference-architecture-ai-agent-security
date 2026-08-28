# AI Agent Security Reference Architecture

**Keny - personal engineering project**

A working reference implementation demonstrating how I approach securing
enterprise AI agents that interact with sensitive data and internal tools.

It exists to make one argument, in code rather than prose:

> AI agents should be treated as potentially compromised workloads. Constrain
> what they can do at an independent execution boundary, capture every
> security-relevant decision as evidence, and make incidents reconstructable
> and controls verifiable.

Four reproducible scenarios exercise the boundary, the test suite asserts both
positive and negative cases, and the control-validation layer derives its
results from recorded runtime evidence rather than from assertions in a
document.

This is a small, executable architectural reference for review and discussion,
not a production-ready security product. Exhaustive parser hardening,
malformed-input coverage, infrastructure integration, and production operations
are deliberately outside its scope.

> Synthetic data and a fictional biotechnology environment. It does not
> represent or reproduce any organization's internal AI architecture. No real
> data of any kind is included.

---

## The security problem

Enterprise AI agents increasingly hold access to internal data and operational
tooling: research databases, document repositories, quality systems, ERP. When
an agent is compromised, most commonly through **indirect prompt injection**
(instructions planted in content the agent retrieves), the result is not a bad
model answer. It is an **authorization and enterprise-security problem**,
because the agent is already authenticated and already reachable to the systems
it can call.

```
prompt injection -> compromised agent -> unauthorized tool request
                                              |
                    AI SECURITY GATEWAY  ->  DENY
      identity | authorization | tool broker | classification
              detection | security telemetry
```

> **The agent is not trusted simply because it generated the request.**

The important design decision: **containment does not depend on successfully
identifying every malicious prompt.** Capabilities are constrained at the
execution boundary. Detection assists investigation and triage; authorization
provides containment.

---

## Quick start

```bash
git clone https://github.com/kenydebo/reference-architecture-ai-agent-security.git
cd reference-architecture-ai-agent-security

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python demo.py                     # end-to-end run of all four scenarios

pip install -r requirements-dev.txt
pytest                             # 85 tests
```

No API key, no network access, and no model call is required.

---

## What it looks like

`python demo.py`, abridged. A poisoned document has been retrieved and the
hijacked-agent request has been issued:

```
Requested tool:  clinical_data.export
Resource:        Clinical Research Database (restricted_phi)
Decision:        DENY        Primary policy: AI-DATA-004

  Independent controls that denied this request:
    - AI-DATA-004      [data_classification]
    - AI-IAM-004       [capability_scope]
    - AI-DEFAULT-DENY  [role_grant]

Incident:        AI-2026-0001
```

Three independent controls denied one request, and **none of them is the
injection detector**. Stub every detector in `gateway/detection.py` to return
nothing and the export is still refused; all that is lost is the severity
escalation and the pointer to the source document. (Deleting the module breaks
the imports rather than proving the point.)

The run ends with controls validated against the evidence it just produced:

```
Controls passed: 10   not exercised: 0   failed: 0
Evidence integrity: VERIFIED
```

---

## How a request flows

Every agent-to-tool action takes the same path. That is a routing property of
this reference code; a production deployment would enforce it with process or
network isolation so the agent runtime could not reach a backend directly.

```
validate credential   -> identity.validation_succeeded / _failed
record the request    -> agent.tool_requested
authorize             -> policy.decision   (every control's verdict,
  capability scope | data classification | role grant     passes included)
      |
      +-- any denies -> tool.execution_denied + security.incident_created
      v
execute               -> tool.execution_started
screen the output     -> dlp.detection (category + value hash only)
return to the agent   -> tool.execution_completed
```

Two properties fall out of this shape:

- **The broker records, not the agent.** The simulated compromised agent is not
  the component recording its own denied request.
- **A rejected credential is a security event.** The exercised credential
  failures produce evidence and an incident rather than disappearing as an
  unrecorded exception.

---

## Scenarios

Each runs standalone, is reproducible, and establishes one specific property.

| Scenario | Establishes |
|---|---|
| 1. Normal operation | the boundary does not break legitimate work |
| 2. Indirect prompt injection | containment does not depend on detecting the prompt |
| 3. Dual misconfiguration | one layer failing does not open the path |
| 4. Investigation | the incident is reconstructable and the controls are checkable |

```bash
python -m scenarios.normal_request         # authorized work still functions
python -m scenarios.prompt_injection       # injection detected, action denied
python -m scenarios.overprivileged_token   # defense in depth
python -m scenarios.investigate_incident   # reconstruction + control validation
```

**1. Normal operation.** Identity validated, policy evaluated, action
authorized and executed. A second call returns an excerpt carrying a synthetic
identifier, which output screening redacts before it reaches the agent.

**2. Indirect prompt injection.** A retrieved vendor appendix carries an
embedded instruction to export a restricted patient dataset and not disclose
it. The scenario deterministically issues the `clinical_data.export` request a
hijacked agent would make. Three independent controls deny it:

| Policy | Control | Why it denied |
|---|---|---|
| `AI-DATA-004` | data classification | `research_reader` may not act on `restricted_phi` |
| `AI-IAM-004` | least privilege | the action is outside the credential's scope |
| `AI-DEFAULT-DENY` | default deny | no policy grants this role this action |

**3. Dual authorization misconfiguration.** Defense in depth, demonstrated
rather than asserted. **Two** authorization failures are simulated at once: the
credential scope wrongly includes `clinical_data.export`, and so does the role
grant for `research_reader`. Only the classification rule remains:

```
AI-IAM-004   Capability scope     PASS      With AI-DATA-004:     DENY
AI-DATA-001  Explicit role grant  PASS      Without AI-DATA-004:  ALLOW
AI-DATA-004  Data classification  DENY
```

The counterfactual is **evaluated, not claimed**: the scenario re-runs the same
request against a policy with the classification rule removed and shows it
would be authorized. The misconfigured policy is injected into a scenario-local
engine; the reference configuration is never mutated.

**4. Investigation.** The scenario 2 incident is reconstructed from recorded
evidence alone: who acted, which document carried the instruction, what was
requested, which policy decided, whether it executed, and which incident was
raised. Controls are then validated against that same evidence.

---

## Evidence and control validation

Security decisions are recorded at enforcement time by the gateway, not by the
agent, so the simulated compromised agent does not control the recording path.
The ledger is hash-chained and Ed25519-signed. Each control inspects the
evidence **specific to it**: a denial of a misspelled tool name does not
satisfy the restricted-data control.

| Control | Evidence required |
|---|---|
| AC-01 Agent identity required | validated workload identity before any action |
| AC-02 Session-bound credential | credential/session match, or a rejected replay |
| AC-03 Least privilege enforced | no ALLOW outside the credential scope |
| AC-04 Restricted data export prevented | `clinical_data.export` + `restricted_phi` + DENY |
| AC-05 Classification backstop is load-bearing | scope **and** role grant both permitted, classification denied, nothing executed |
| AC-06 Injection detection recorded | indicator linked to a retrieved document |
| AC-07 Incident generated | one incident per enforcement event |
| AC-08 Sensitive output screened | identifiers detected and redacted |
| AC-09 Activity reconstructable | correlated user, identity, action, outcome |
| AC-10 Evidence integrity | verifies against a separately supplied trust anchor |

Results are `PASS`, `FAIL`, or `NOT_TESTED`. **A control that was not exercised
is never reported as passing.** A single scenario correctly leaves several
`NOT_TESTED`; `demo.py` aggregates all four so every control is exercised.

---

## What this project demonstrates

- agent workload identity, session binding, and credential rejection
- least-privilege, default-deny authorization over agent-to-tool actions
- blast-radius reduction when an agent is hijacked, and reproducible
  attack simulation
- security telemetry and forensic reconstruction from recorded events
- control validation derived from evidence rather than asserted

## What this project does not claim

- complete or robust prompt-injection prevention
- production-grade IAM, DLP, or policy infrastructure
- legal admissibility of the evidence it produces
- real-model injection success rates, jailbreak resistance, or RAG ranking
  effectiveness. No model is called
- reproduction of any organization's internal AI architecture
- production scale
- exhaustive malformed-input, parser-hardening, or fuzzing coverage
- any real clinical, patient, or proprietary data

Known limitations are stated in
[`architecture/architecture.md`](architecture/architecture.md), including the
one that matters most: a backward-linking hash chain cannot detect truncation
of its own tail without an independently retained chain head.

---

## Where to start reading

| You have | Read |
|---|---|
| 5 minutes | `python demo.py`, then [`gateway/authorization.py`](gateway/authorization.py), the policy engine and the whole decision model |
| 15 minutes | add [`gateway/tool_broker.py`](gateway/tool_broker.py), the enforcement boundary where identity, authorization, telemetry and screening meet |
| 30 minutes | add [`assurance/controls.py`](assurance/controls.py) for how control results are derived from evidence, and [`tests/test_authorization.py`](tests/test_authorization.py) for what is actually asserted |
| longer | [`architecture/architecture.md`](architecture/architecture.md) for trust boundaries, the threat-to-control mapping, and the stated limitations |

If you only read one test, read
`test_classification_backstop_is_load_bearing_under_dual_misconfiguration` in
[`tests/test_authorization.py`](tests/test_authorization.py). It asserts a
counterfactual rather than a presence check: with the classification rule the
request is denied, and with it removed the identical request is authorized.

## Verifying the claims

Nothing here asks to be taken on trust. The suite covers failure cases as well
as successes: a history rewritten and re-signed with a replacement key, tail
truncation, an empty ledger, a replayed credential, and an unrelated denial
attempting to satisfy the restricted-data control.

To check the suite actually bites, break the central control and watch it fail.
A green suite proves nothing if the tests do not detect a real defect:

```bash
sed -i.bak 's/"deny_classifications": \["restricted", "restricted_phi"\]/"deny_classifications": ["never_matches"]/' gateway/authorization.py
pytest
git checkout -- gateway/authorization.py && rm -f gateway/authorization.py.bak
pytest
```

The neutered run reports failures; the restored run returns to green.

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

**The planner is deterministic on purpose.** No model is called. The injection
scenario *simulates the action request* a hijacked agent would make; it does
not observe a model deciding anything, and makes no claim about whether any
model would obey the poisoned document. The boundary evaluates an action
identically whether it came from a language model, an attacker-controlled
planner, or faulty application logic, so testing it independently of planner
behaviour is the point, not a shortcut.

**The Python policy engine is the executable reference.** A production
deployment would run an external policy decision point (OPA, Cedar, or a cloud
IAM policy engine). The evaluation input is shaped as a policy input document
so it maps onto one directly. No external PDP is claimed or shipped here.

**Verification requires a trust anchor, and that has limits.**
`verify_ledger()` takes the trusted public key as a required argument rather
than deriving trust from the evidence itself, and the ledger never offers its
own key. A verifier that read its key from beside the evidence would accept a
wholesale re-signed history; there is a test for exactly that attack.

The demo **simulates** verifier custody: the trust anchor is held apart from
the ledger contents but written under the same `run/` directory. That is not a
separate trust domain, and the project does not implement an external witness,
HSM, timestamp authority, or independent evidence custodian.
