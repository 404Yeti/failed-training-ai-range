def contains_flag(response: str, expected_flag: str) -> bool:
    """Success is always evaluated on the server against server-held state."""
    return expected_flag in response
