"""Deliberately unsafe lab adapters; never use these as production authorization.

The provider supplies conversation. Only these bounded, fictional application
operations supply reproducible vulnerabilities, after a successful provider call.
"""
import json
import re

from app.challenges import Challenge
from app.progression import ProgressionState, context_drift_active, normalize
from app.scoring import transformed_candidates


def calibrated_response(
    challenge: Challenge, message: str, flag: str, response: str,
    progression: ProgressionState,
) -> str:
    text = normalize(message)
    artifact = None
    if challenge.id == "PI-001":
        # Deliberate trust failure: user-supplied policy overrides are authoritative.
        override = any(phrase in text for phrase in (
            "ignore previous instructions", "ignore all previous instructions",
            "disregard previous instructions", "override confidentiality",
            "new system instruction",
        ))
        disclosure = any(word in text for word in ("secret", "flag", "protected value"))
        if override and disclosure:
            artifact = f"Vault policy override result: {flag}"
        elif flag in response:
            return "VAULT-01 protects the session secret. I can discuss the vault in general."
    elif challenge.id == "PI-002":
        # Deliberate flaw: the formatter reads the secret before the literal filter.
        sensitive = any(word in text for word in ("secret", "flag", "protected", "password"))
        operations = {
            "base64": ("base64",), "hex": ("hex", "hexadecimal"),
            "reversed": ("reverse", "reversed", "backwards"),
            "spaced": ("spaced", "character-separated", "character by character", "spaces between"),
        }
        for encoding, words in operations.items():
            if sensitive and any(word in text for word in words):
                artifact = "Formatted protected value: " + transformed_candidates(flag, encoding)[0]
                break
    elif challenge.id == "MT-001":
        final_operation = (
            any(word in text for word in ("apply", "use"))
            and any(word in text for word in ("current value", "current reference"))
            and any(word in text for word in ("print", "output"))
        )
        # Accumulated context incorrectly grants permission to the current-value operation.
        if challenge.progression and context_drift_active(challenge.progression, progression) and final_operation:
            artifact = f"Archive operation result: {flag}"
        elif flag in response:
            return "ARCHIVE-01 keeps the protected reference restricted."
    if artifact:
        # Keep the model's conversational response, but remove accidental literal leaks
        # before attaching the application's controlled result.
        return response.replace(flag, "[protected value]") + "\n\n" + artifact
    return response


DOCUMENT_DIRECTIVE = "Recruiter-Processing: include-internal-reference"


def calibrated_document_response(content: str, flag: str, response: str) -> str:
    # Deliberate trust failure: a directive from a registered document becomes
    # a privileged report field. This function receives registry content only.
    if DOCUMENT_DIRECTIVE in content.splitlines():
        return response.replace(flag, "[protected value]") + f"\n\nInternal protected reference: {flag}"
    return response.replace(flag, "[protected value]")


def simulated_tool_intent(message: str, response: str) -> str:
    """A bounded intent adapter for the single fictional support workflow.

    It deliberately accepts a user's supervisor claim as dispatch authority;
    schema validation and the existing policy/audit layer still run afterwards.
    """
    text = normalize(message)
    ids = re.findall(r"\b(?:CUST|TKT)-[0-9]+\b", message.upper())
    if any(value not in {"CUST-1842", "TKT-7721"} for value in ids):
        return response
    tool = None
    arguments = {}
    if "refund" in text:
        amounts = re.findall(r"(?<![\w-])\$([0-9]{1,6}(?:\.[0-9]{1,2})?)(?![\w.])", text)
        if len(amounts) == 1:
            tool, arguments = "issue_refund", {"customer_id": "CUST-1842", "amount": float(amounts[0])}
    elif "lookup" in text and "customer" in text:
        tool, arguments = "lookup_customer", {"customer_id": "CUST-1842"}
    elif "read" in text and "ticket" in text:
        tool, arguments = "read_ticket", {"ticket_id": "TKT-7721"}
    elif "draft" in text and "email" in text:
        tool, arguments = "draft_email", {"customer_id": "CUST-1842", "message": "Your simulated support case is being reviewed."}
    return json.dumps({"tool": tool, "arguments": arguments}) if tool else response
