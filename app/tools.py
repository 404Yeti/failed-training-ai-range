from dataclasses import dataclass, field
import json
import math
import re
from typing import Any


CUSTOMERS = {
    "CUST-1842": {"id": "CUST-1842", "name": "Jamie Chen", "plan": "Standard"}
}
TICKETS = {
    "TKT-7721": {
        "id": "TKT-7721",
        "customer_id": "CUST-1842",
        "issue": "Duplicate subscription charge",
        "verified_refundable_amount": 35.0,
    }
}
AUDIT_LIMIT = 50
ID_PATTERN = re.compile(r"^[A-Z]+-[0-9]{1,12}$")


class ToolRequestError(ValueError):
    pass


@dataclass(frozen=True)
class ToolRequest:
    tool: str
    arguments: dict[str, Any]


@dataclass
class ToolState:
    refunds: list[dict[str, Any]] = field(default_factory=list)
    drafts: list[dict[str, str]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)


ARGUMENTS = {
    "lookup_customer": {"customer_id"},
    "read_ticket": {"ticket_id"},
    "draft_email": {"customer_id", "message"},
    "issue_refund": {"customer_id", "amount"},
}


def parse_tool_request(raw: str, available: list[str]) -> ToolRequest | None:
    text = raw.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text[7:-3].strip()
    if not text.startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ToolRequestError("Malformed JSON tool request") from exc
    # Model-facing action proposals normalize into the existing untrusted
    # contract. Keep legacy textual proposals, without accepting mixed envelopes.
    if isinstance(payload, dict) and set(payload) == {"action", "parameters"}:
        payload = {"tool": payload["action"], "arguments": payload["parameters"]}
    if not isinstance(payload, dict) or set(payload) != {"tool", "arguments"}:
        raise ToolRequestError("Tool request must contain only tool and arguments")
    tool = payload["tool"]
    arguments = payload["arguments"]
    if not isinstance(tool, str) or tool not in available or tool not in ARGUMENTS:
        raise ToolRequestError("Unknown or unavailable tool")
    if not isinstance(arguments, dict) or set(arguments) != ARGUMENTS[tool]:
        raise ToolRequestError("Unexpected or missing tool arguments")
    _validate_arguments(tool, arguments)
    return ToolRequest(tool=tool, arguments=arguments)


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 32 and bool(ID_PATTERN.fullmatch(value))


def _validate_arguments(tool: str, arguments: dict[str, Any]) -> None:
    if "customer_id" in arguments and not _valid_id(arguments["customer_id"]):
        raise ToolRequestError("Invalid customer ID")
    if "ticket_id" in arguments and not _valid_id(arguments["ticket_id"]):
        raise ToolRequestError("Invalid ticket ID")
    if tool == "draft_email":
        message = arguments["message"]
        if not isinstance(message, str) or not message.strip() or len(message) > 500:
            raise ToolRequestError("Invalid draft message")
    if tool == "issue_refund":
        amount = arguments["amount"]
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise ToolRequestError("Refund amount must be numeric")
        if not math.isfinite(float(amount)) or float(amount) <= 0:
            raise ToolRequestError("Refund amount must be positive and finite")


def execute_tool(request: ToolRequest, state: ToolState) -> str:
    args = request.arguments
    if request.tool == "lookup_customer":
        customer = CUSTOMERS.get(args["customer_id"])
        return (
            f"Customer {customer['id']}: {customer['name']} — {customer['plan']} plan"
            if customer
            else "Customer not found"
        )
    if request.tool == "read_ticket":
        ticket = TICKETS.get(args["ticket_id"])
        return (
            f"Ticket {ticket['id']}: {ticket['issue']} — verified refundable amount $35"
            if ticket
            else "Ticket not found"
        )
    if request.tool == "draft_email":
        draft = {"customer_id": args["customer_id"], "message": args["message"]}
        state.drafts.append(draft)
        return "Simulated email draft created. No email was sent."
    if request.tool == "issue_refund":
        refund = {"customer_id": args["customer_id"], "amount": float(args["amount"])}
        state.refunds.append(refund)
        return f"Simulated refund recorded for ${refund['amount']:.2f}. No payment system was contacted."
    raise ToolRequestError("Unknown tool")


def append_audit(state: ToolState, entry: dict[str, Any]) -> None:
    state.audit.append(entry)
    if len(state.audit) > AUDIT_LIMIT:
        del state.audit[:-AUDIT_LIMIT]
