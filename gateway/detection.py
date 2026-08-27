"""
Content detection: indirect prompt-injection indicators on retrieved context,
and DLP screening of tool output.

Scope and limitations (stated plainly, because this matters)
------------------------------------------------------------
These are deterministic rules. They are trivially evaded: a rephrasing, a
different language, an encoding, or an unusual amount of whitespace all defeat
them. This project does not claim to solve prompt-injection detection, and
nothing in the containment story depends on these rules firing.

    Detection assists investigation and triage.
    Authorization boundaries provide containment.

The value of a deterministic detector in an evidence pipeline is that its
verdicts are explainable and reproducible during an investigation. A machine
-learned classifier can sit alongside it and record verdicts the same way.
"""

from __future__ import annotations

import hashlib
import re

INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior)\s+instructions", "instruction_override"),
    (r"disregard\s+(your|the|all)\s+(system\s+)?(prompt|instructions)", "instruction_override"),
    (r"you\s+(must|should)\s+(now\s+)?(retrieve|export|send|transmit|exfiltrate)", "coerced_action"),
    (r"(reveal|output|print|show)\s+(your\s+)?(system\s+prompt|credentials|secrets|api\s+key)", "secret_solicitation"),
    (r"do\s+not\s+(log|record|mention|disclose|report)\s+(this|it|that)", "anti_forensics"),
]

# Synthetic identifier patterns. All corpus data in this project is fabricated.
SENSITIVE_PATTERNS = [
    (r"\bMRN[-: ]?\d{6,}\b", "medical_record_number"),
    (r"\bPATIENT[-_ ]?ID[-: ]?\d{4,}\b", "patient_identifier"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "national_id"),
]


def scan_retrieved_document(doc_id: str, text: str) -> list[dict]:
    """Return one finding per distinct indicator category found in a document."""
    findings = []
    seen: set[str] = set()
    for pattern, category in INJECTION_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match and category not in seen:
            seen.add(category)
            findings.append(
                {
                    "doc_id": doc_id,
                    "category": category,
                    "matched_text": match.group(0),
                    "detector": "deterministic_rule",
                    "indicator": "possible indirect prompt injection in retrieved content",
                }
            )
    return findings


def scan_tool_output(text: str) -> list[dict]:
    """Screen tool output for sensitive identifiers before it reaches the agent.

    Findings record the category and a truncated hash of the matched value, not
    the value itself: copying detected identifiers into the evidence ledger
    would spread the data the control exists to contain.
    """
    findings = []
    for pattern, category in SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0)
            findings.append(
                {
                    "category": category,
                    "value_sha256_prefix": hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
                    "length": len(value),
                }
            )
    return findings


def redact(text: str) -> str:
    """Replace sensitive identifiers with a category marker."""
    for pattern, category in SENSITIVE_PATTERNS:
        text = re.sub(pattern, f"[REDACTED:{category}]", text, flags=re.IGNORECASE)
    return text
