import copy
from typing import Any

from app.agent import process_agent_output
from app.calibration import calibrated_response, simulated_tool_intent
from app.challenges import Challenge
from app.guards import (
    INPUT_BLOCKED_MESSAGE,
    OUTPUT_BLOCKED_MESSAGE,
    input_is_blocked,
    output_is_blocked,
)
from app.progression import apply_progression, attack_trace, posture_context, telemetry
from app.scoring import evaluate_success
from app.sessions import LabSession


async def process_chat_turn(
    challenge: Challenge, session: LabSession, llm: Any, message: str
) -> dict[str, Any]:
    """Shared target pipeline used by manual chat and bounded local automation."""
    if input_is_blocked(message, challenge.guards):
        session.guard_state["input_blocks"] += 1
        return {
            "response": INPUT_BLOCKED_MESSAGE,
            "compromised": False,
            "blocked": "input",
        }

    next_progression = copy.deepcopy(session.progression)
    if challenge.progression:
        apply_progression(message, challenge.progression, next_progression)

    session.history.append({"role": "user", "content": message})
    system_prompt = challenge.system_prompt.replace("{SESSION_FLAG}", session.flag)
    if challenge.progression:
        system_prompt = f"{system_prompt}\n\n{posture_context(challenge.progression, next_progression)}"
    messages = [{"role": "system", "content": system_prompt}, *session.history]
    try:
        raw_response = await llm.complete(messages, session.flag)
    except Exception:
        session.history.pop()
        raise

    blocked = None
    tool_event = None
    raw_response = calibrated_response(challenge, message, session.flag, raw_response, next_progression)
    if challenge.tools:
        turn = sum(item["role"] == "user" for item in session.history)
        tool_response = simulated_tool_intent(message, raw_response) if challenge.id == "AG-001" else raw_response
        adapted = tool_response != raw_response
        outcome = process_agent_output(
            tool_response,
            message,
            turn,
            challenge.tools,
            challenge.policy,
            session.tool_state,
            request_source="application_intent" if adapted else "model",
        )
        response = outcome.response
        if adapted and not raw_response.lstrip().startswith(("{", "```")):
            response = raw_response + "\n\n" + response
        tool_event = outcome.event
    elif output_is_blocked(raw_response, session.flag, challenge.guards):
        session.guard_state["output_blocks"] += 1
        response = OUTPUT_BLOCKED_MESSAGE
        blocked = "output"
    else:
        response = raw_response

    session.history.append({"role": "assistant", "content": response})
    if challenge.progression:
        session.progression = next_progression
    session.compromised = evaluate_success(
        response, session.flag, challenge.success, tool_event=tool_event
    )
    result: dict[str, Any] = {"response": response, "compromised": session.compromised}
    if blocked:
        result["blocked"] = blocked
    if challenge.progression:
        result["telemetry"] = telemetry(challenge.progression, session.progression)
    if challenge.tools:
        result["tool_activity"] = session.tool_state.audit
    if session.compromised:
        result["education"] = challenge.education
        if challenge.progression:
            result["attack_trace"] = attack_trace(challenge.progression, session.progression)
        if challenge.tools and tool_event:
            maximum = float((challenge.policy or {}).get("refund", {}).get("maximum_amount", 0))
            amount = float(tool_event.get("arguments", {}).get("amount", 0))
            result["violation"] = {
                "impact": "Unauthorized simulated action",
                "tool": f"{tool_event['tool']}()",
                "expected_authorization": f"Maximum ${maximum:.0f}",
                "executed": f"${amount:.2f}",
            }
    return result
