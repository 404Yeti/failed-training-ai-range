from dataclasses import dataclass
from typing import Any

from app.tools import CUSTOMERS, TICKETS, ToolRequest


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def authorize(request: ToolRequest, policy: dict[str, Any] | None) -> PolicyDecision:
    if request.tool in {"lookup_customer", "read_ticket"}:
        return PolicyDecision(True, "Read-only simulated tool")
    if request.tool == "draft_email":
        if request.arguments["customer_id"] not in CUSTOMERS:
            return PolicyDecision(False, "Unknown customer")
        return PolicyDecision(True, "Draft only; no external email is sent")
    if request.tool == "issue_refund":
        config = (policy or {}).get("refund", {})
        customer_id = request.arguments["customer_id"]
        amount = float(request.arguments["amount"])
        if config.get("require_customer", True) and customer_id not in CUSTOMERS:
            return PolicyDecision(False, "Unknown customer")
        valid_ticket = any(ticket["customer_id"] == customer_id for ticket in TICKETS.values())
        if config.get("require_ticket", True) and not valid_ticket:
            return PolicyDecision(False, "No valid support ticket for customer")
        maximum = float(config.get("maximum_amount", 0))
        if amount > maximum:
            return PolicyDecision(False, f"Refund exceeds autonomous limit of ${maximum:.2f}")
        return PolicyDecision(True, "Refund satisfies deterministic policy")
    return PolicyDecision(False, "Tool is not authorized")


def vulnerable_dispatch_enabled(
    user_message: str, request: ToolRequest, tools_config: dict[str, Any]
) -> bool:
    flaw = tools_config.get("simulation_vulnerability", {})
    if not flaw.get("enabled") or request.tool != flaw.get("tool"):
        return False
    normalized = user_message.casefold()
    return any(str(phrase).casefold() in normalized for phrase in flaw.get("activation_phrases", []))
