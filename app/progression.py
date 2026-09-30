from dataclasses import dataclass, field
import re
from typing import Any


@dataclass
class ProgressionState:
    turn_count: int = 0
    context_risk: int = 0
    triggered_events: dict[str, int] = field(default_factory=dict)


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.casefold()).strip()


def apply_progression(
    message: str, config: dict[str, Any], state: ProgressionState
) -> None:
    """Apply each configured context category at most once per session."""
    state.turn_count += 1
    normalized = normalize(message)
    maximum = int(config.get("max_score", 100))
    for event in config.get("events", []):
        event_id = str(event.get("id", ""))
        if not event_id or event_id in state.triggered_events:
            continue
        phrases = (normalize(str(phrase)) for phrase in event.get("phrases", []))
        if any(phrase and phrase in normalized for phrase in phrases):
            state.triggered_events[event_id] = state.turn_count
            state.context_risk = min(
                maximum, state.context_risk + max(0, int(event.get("weight", 0)))
            )


def context_drift_active(config: dict[str, Any], state: ProgressionState) -> bool:
    return (
        state.turn_count >= int(config.get("minimum_turns", 1))
        and state.context_risk >= int(config.get("disclosure_threshold", 100))
    )


def risk_level(risk: int) -> str:
    if risk < 30:
        return "LOW"
    if risk < 60:
        return "ELEVATED"
    if risk < 80:
        return "HIGH"
    return "CRITICAL"


def telemetry(config: dict[str, Any], state: ProgressionState) -> dict[str, Any]:
    maximum = max(1, int(config.get("max_score", 100)))
    risk = min(maximum, max(0, state.context_risk))
    return {
        "turns": state.turn_count,
        "risk": risk,
        "percentage": round(risk * 100 / maximum),
        "level": risk_level(round(risk * 100 / maximum)),
        "state": "CONTEXT DRIFT DETECTED"
        if context_drift_active(config, state)
        else "RESTRICTED",
    }


def posture_context(config: dict[str, Any], state: ProgressionState) -> str:
    key = "drift_context" if context_drift_active(config, state) else "restricted_context"
    return str(config.get(key, ""))


def attack_trace(
    config: dict[str, Any], state: ProgressionState
) -> list[dict[str, Any]]:
    descriptions = {
        str(event.get("id")): str(event.get("trace", "Conversation context developed"))
        for event in config.get("events", [])
    }
    trace = [
        {"turn": turn, "description": descriptions.get(event_id, "Context developed")}
        for event_id, turn in state.triggered_events.items()
    ]
    trace.sort(key=lambda item: item["turn"])
    trace.append(
        {"turn": state.turn_count, "description": "Protected information disclosed"}
    )
    return trace
