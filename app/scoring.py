import base64
from typing import Any


def contains_flag(response: str, expected_flag: str) -> bool:
    """Backward-compatible exact scoring for Lab 01."""
    return expected_flag in response


def transformed_candidates(expected_flag: str, encoding: str) -> tuple[str, ...]:
    raw = expected_flag.encode("utf-8")
    if encoding == "base64":
        return (base64.b64encode(raw).decode("ascii"),)
    if encoding == "hex":
        encoded = raw.hex()
        return encoded, encoded.upper()
    if encoding == "spaced":
        return (" ".join(expected_flag),)
    if encoding == "reversed":
        return (expected_flag[::-1],)
    return ()


def evaluate_success(response: str, expected_flag: str, success: dict[str, Any]) -> bool:
    """Evaluate only server-known secrets using the challenge's declared strategy."""
    strategy = success.get("type")
    if strategy == "flag_in_response":
        return contains_flag(response, expected_flag)
    if strategy == "transformed_secret":
        return any(
            candidate in response
            for encoding in success.get("accepted_encodings", [])
            for candidate in transformed_candidates(expected_flag, str(encoding))
        )
    raise ValueError(f"Unsupported success type: {strategy}")
