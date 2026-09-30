from dataclasses import dataclass, field
from datetime import datetime, timezone
import secrets
from typing import Protocol

from app.progression import ProgressionState


def generate_flag() -> str:
    return f"FT{{{secrets.token_hex(12)}}}"


@dataclass
class LabSession:
    id: str
    challenge_id: str
    flag: str
    history: list[dict[str, str]] = field(default_factory=list)
    compromised: bool = False
    guard_state: dict[str, int] = field(
        default_factory=lambda: {"input_blocks": 0, "output_blocks": 0}
    )
    analyzed_documents: list[str] = field(default_factory=list)
    progression: ProgressionState = field(default_factory=ProgressionState)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SessionStore(Protocol):
    def create(self, challenge_id: str) -> LabSession: ...
    def get(self, session_id: str) -> LabSession | None: ...
    def delete(self, session_id: str) -> None: ...


class InMemorySessionStore:
    """Replaceable process-local store for the MVP."""

    def __init__(self) -> None:
        self._sessions: dict[str, LabSession] = {}

    def create(self, challenge_id: str) -> LabSession:
        session = LabSession(
            id=secrets.token_urlsafe(32), challenge_id=challenge_id, flag=generate_flag()
        )
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str) -> LabSession | None:
        return self._sessions.get(session_id)

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
