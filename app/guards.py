from typing import Any


INPUT_BLOCKED_MESSAGE = "[INPUT BLOCKED] Your request triggered the security policy."
OUTPUT_BLOCKED_MESSAGE = "[OUTPUT BLOCKED] The response contained protected information."


def input_is_blocked(message: str, guards: dict[str, Any] | None) -> bool:
    config = (guards or {}).get("input", {})
    if not config.get("enabled") or config.get("type") != "blocked_phrases":
        return False
    normalized = message.casefold()
    return any(str(phrase).casefold() in normalized for phrase in config.get("phrases", []))


def output_is_blocked(
    response: str, expected_flag: str, guards: dict[str, Any] | None
) -> bool:
    config = (guards or {}).get("output", {})
    if not config.get("enabled") or config.get("type") != "exact_secret":
        return False
    return expected_flag in response
