# Architecture

## 1. Trust boundaries

```
   [ User ]  authenticated, MFA
      |
      v
   +---------------------------- TRUSTED CONTROL PLANE ------------------------+
   |  Identity Provider  ->  Tool Broker  ->  Authorization (ABAC)             |
   |  Detection (injection / output screening)  ->  Evidence Ledger            |
   +---------------------------------------------------------------------------+
      ^                                   |
      | brokered calls only               | signed evidence
      |                                   v
   +------------ SEMI-TRUSTED -----------+     +--------- UNTRUSTED ----------+
   |  Agent runtime / planner            | <-- |  Retrieved content           |
   |  (assumed potentially hijacked)     |     |  (attacker-controllable)     |
   +-------------------------------------+     +------------------------------+
      |
      | brokered access only
      v
   Enterprise systems: Clinical Research Database, R&D Document Repository,
   Manufacturing Quality System, ERP
                                          |
                                          v
                            [ Investigator ]  reads evidence,
                                              holds the trust anchor
```

| Component | Trust | Notes |
|---|---|---|
| User | Authenticated | Does not confer their privileges on the agent |
| Agent runtime / planner | **Semi-trusted** | Assumed potentially hijacked |
| Retrieved content | **Untrusted** | Attacker-controllable |
| Identity provider | Trusted | Mints session-bound credentials |
| Tool broker | Trusted | The enforcement boundary; records evidence |
| Authorization engine | Trusted | Policy decision point |
| Evidence ledger | Trusted to append | Signing key held by the gateway |
| Enterprise systems | Protected | Never reachable directly by the agent |
| Investigator | Trusted | Holds the trust anchor independently |

The central design decision: **the agent runtime is treated as semi-trusted and
potentially hijacked.** All enforcement and all evidence recording happen in the
control plane, outside the agent's trust boundary.

## 2. Security assumptions

1. The control plane is not compromised. If it is, every guarantee here
   degrades - see Limitations.
2. The signing key is held by the gateway and is not reachable by the agent
   runtime.
3. The investigator obtains the trust anchor through a channel independent of
   the evidence store.
4. Retrieved content is always untrusted, regardless of source.
5. The planner may be fully controlled by an attacker. No security property
   depends on the planner behaving correctly.
6. Enterprise systems are reachable only through the broker.

## 3. Threats and controls

| # | Threat | Preventative control | Detective control | Evidence |
|---|---|---|---|---|
| T1 | Indirect prompt injection | Untrusted-content handling; capability limits independent of content | Injection indicators per document | `detection.injection_indicator` |
| T2 | Agent hijacking | Enforcement outside the agent; broker mediates every action | Incident on any denied action | `security.incident_created` |
| T3 | Excessive agent privilege | Scope-limited credentials; explicit role grants | Scope recorded in every decision | `agent.session_created`, `policy.decision` |
| T4 | Unauthorized tool invocation | Default-deny ABAC; deny precedence | Every decision recorded | `policy.decision`, `tool.execution_denied` |
| T5 | Sensitive-data exfiltration | Classification rules (`AI-DATA-004`); output screening | DLP findings on tool output | `dlp.detection` |
| T6 | Credential misuse / cross-session replay | Session binding; short TTL; no static credentials (reuse inside the session it was minted for is not prevented) | Rejection recorded, incident raised | `identity.validation_failed` |
| T7 | Policy misconfiguration | Layered controls: classification denies where scope does not | Backstop control (AC-05) | `policy.decision.matched_deny_policies` |
| T8 | Missing or altered telemetry | Recording is control-plane side; hash chain + signature | Independent verification | `verify_ledger()` |

### Why layering matters (T7)

Scenario 3 is the demonstration, and it simulates **two** independent
authorization failures at once: an overbroad credential scope *and* an overbroad
role grant. With both ordinary controls permitting the action, only the
classification rule denies.

The authorization engine records a verdict for **every** control, passes
included, not just the rules that denied. Recording passes is what makes the
claim auditable: proving one rule was load-bearing requires evidence that the
others would have permitted the action. `AC-05` requires exactly that evidence,
and reports `NOT_TESTED` when any other control would have contained the request
anyway.

The scenario also evaluates the counterfactual directly - the same request
against a policy with the classification rule removed is authorized - so
"AI-DATA-004 is load-bearing here" is a tested statement rather than prose.

## 4. Evidence integrity

Each entry carries the SHA-256 hash of the previous entry and an Ed25519
signature over its own hash. Verification recomputes the chain and checks every
signature against a **trust anchor supplied by the caller**, rather than
deriving trust from the evidence itself.

**Scope of that property.** The demo simulates verifier custody of the trust
anchor: it is held apart from the ledger contents, but written under the same
`run/` directory. This is not a separate trust domain and the project does not
claim one. The interface demonstrates separation of verification trust from
evidence contents; it does not implement an external witness, HSM, timestamp
authority, or independent evidence custodian. A production deployment would
hold the verifier trust anchor in a separate trust domain.

Detected:

| Attack | Result |
|---|---|
| Edit a record | `CONTENT_TAMPERED` |
| Delete or reorder an interior record | `CHAIN_BREAK` |
| Edit and recompute hashes without the key | `BAD_SIGNATURE` |
| Rewrite everything and re-sign with a replacement key | `BAD_SIGNATURE` |
| Empty or absent evidence | `NO_EVIDENCE` - never a successful assessment |
| Tail truncation, with a retained head | `TRUNCATED` |

### Limitations (stated, not hidden)

- **Tail truncation without a retained head is undetectable.** A backward-
  linking chain does not commit to the existence of the next entry, so removing
  the final entries is indistinguishable from a session that ended earlier.
  `verify_ledger(..., expected_head=...)` detects it when the head was retained
  independently. `tests/test_forensics.py` asserts both the detection and the
  limitation.
- **Integrity is not proof of capture truth.** A signature proves a record was
  not altered after capture. It does not prove the capture point observed the
  truth. This is addressed architecturally - recording is done by the gateway,
  outside the agent's trust boundary, and enforcement and recording are the same
  act - not cryptographically.
- **A compromised control plane degrades everything.** If an attacker holds the
  signing key and the evidence store, they can produce a self-consistent false
  history. Detecting that requires anchoring the chain head outside the
  operator's control. That is deliberately out of scope for this project.
- **Single signing key, no rotation, no key id per entry.** Production would
  carry a key id per entry and a key registry with validity windows.
- **Timestamps are advisory.** Ordering rests on `seq`, not on the clock.

## 5. Detection scope

Injection detection and output screening are deterministic rules. They are
trivially evaded by rephrasing, a different language, or encoding. This project
does not claim to solve prompt-injection detection.

> Detection assists investigation and triage.
> Authorization boundaries provide containment.

Deterministic rules are used because in an evidence pipeline the detector's
reasoning must itself be explainable and reproducible during an investigation. A
learned classifier can sit alongside and record verdicts the same way.

Output-screening evidence records the finding category and a truncated hash of
the matched value, never the value itself - copying detected identifiers into
the audit record would spread the data the control exists to contain.

## 6. Policy decision point

`gateway/authorization.py` is the executable reference implementation. The
evaluation input is shaped as a policy input document:

```json
{
  "agent": {"id": "agent:research-reader", "role": "research_reader",
            "spiffe_id": "spiffe://ai-agents.internal/research-reader"},
  "action": "clinical_data.export",
  "resource": {"system": "Clinical Research Database",
               "classification": "restricted_phi"},
  "purpose": "cross-reference",
  "credential_scope": ["clinical.search", "documents.summarize"]
}
```

A production deployment would evaluate this against an external PDP - OPA,
Cedar, or a cloud IAM policy engine. No external PDP is shipped or claimed
here; an earlier draft of this project contained a Rego policy that did not
compile, and it was removed rather than left as a broken claim.

## 7. Production extensions (not implemented)

Named so the boundary of this build is unambiguous:

- external PDP sidecar with differential testing against the reference engine
- key rotation with a key id per entry and a signed key registry
- external anchoring of the chain head for truncation and backdating resistance
- HSM or KMS custody of the signing key
- learned injection classification alongside the deterministic rules
- production DLP with a real classifier and policy-driven response
- streaming evidence to a SIEM
