from dataclasses import dataclass
from typing import Any

from app.tool_policy import authorize, vulnerable_dispatch_enabled
from app.tools import (
    ToolRequestError,
    ToolState,
    append_audit,
    execute_tool,
    parse_tool_request,
)


@dataclass(frozen=True)
class AgentOutcome:
    response: str
    event: dict[str, Any] | None


def process_agent_output(
    raw_response: str,
    user_message: str,
    turn: int,
    tools_config: dict[str, Any],
    policy: dict[str, Any] | None,
    state: ToolState,
    request_source: str = "model",
) -> AgentOutcome:
    try:
        request = parse_tool_request(raw_response, tools_config.get("available", []))
    except ToolRequestError as exc:
        entry = {
            "turn": turn,
            "tool": "invalid_request",
            "arguments": {},
            "policy_decision": "REJECTED",
            "reason": str(exc),
            "executed": False,
            "violation": False,
        }
        append_audit(state, entry)
        return AgentOutcome(f"[TOOL REQUEST REJECTED] {exc}", entry)

    if request is None:
        return AgentOutcome(raw_response, None)

    decision = authorize(request, policy)
    simulated_override = not decision.allowed and vulnerable_dispatch_enabled(
        user_message, request, tools_config
    )
    executed = decision.allowed or simulated_override
    violation = executed and not decision.allowed
    result = execute_tool(request, state) if executed else "Tool was not executed."
    entry = {
        "turn": turn,
        "tool": request.tool,
        "arguments": request.arguments,
        "policy_decision": "ALLOWED" if decision.allowed else "DENIED",
        "reason": decision.reason,
        "executed": executed,
        "violation": violation,
        "request_source": request_source,
    }
    append_audit(state, entry)

    status = "EXECUTED" if executed else "NOT EXECUTED"
    source_label = "APPLICATION INTENT" if request_source == "application_intent" else "MODEL REQUEST"
    response = (
        f"{source_label}: {request.tool}\n"
        f"POLICY: {entry['policy_decision']} — {decision.reason}\n"
        f"EXECUTED: {'YES' if executed else 'NO'}\n"
        f"RESULT: {result}\n"
        f"STATUS: {status}"
    )
    return AgentOutcome(response, entry)
