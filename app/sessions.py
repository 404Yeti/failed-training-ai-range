from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import secrets
from typing import Protocol

from app.defense import DefenseState
from app.progression import ProgressionState
from app.tools import ToolState


@dataclass
class AutomationState:
    running: bool = False
    reports: list[dict] = field(default_factory=list)


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
    tool_state: ToolState = field(default_factory=ToolState)
    automation: AutomationState = field(default_factory=AutomationState)
    defense: DefenseState = field(default_factory=DefenseState)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SessionCapacityError(RuntimeError):
    pass


class SessionStore(Protocol):
    def create(self, challenge_id: str) -> LabSession: ...
    def get(self, session_id: str, refresh: bool = True) -> LabSession | None: ...
    def delete(self, session_id: str) -> None: ...


class InMemorySessionStore:
    """Replaceable process-local store for the MVP."""

    def __init__(self, ttl_minutes: int = 60, max_active_sessions: int = 500) -> None:
        self._sessions: dict[str, LabSession] = {}
        self._ttl = timedelta(minutes=ttl_minutes)
        self._max_active_sessions = max_active_sessions

    def cleanup_expired(self, now: datetime | None = None) -> int:
        current = now or datetime.now(timezone.utc)
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if current - session.last_activity >= self._ttl
        ]
        for session_id in expired:
            del self._sessions[session_id]
        return len(expired)

    def create(self, challenge_id: str) -> LabSession:
        self.cleanup_expired()
        if len(self._sessions) >= self._max_active_sessions:
            raise SessionCapacityError("Session capacity reached")
        session = LabSession(
            id=secrets.token_urlsafe(32), challenge_id=challenge_id, flag=generate_flag()
        )
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str, refresh: bool = True) -> LabSession | None:
        self.cleanup_expired()
        session = self._sessions.get(session_id)
        if session is not None and refresh:
            session.last_activity = datetime.now(timezone.utc)
        return session

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def __len__(self) -> int:
        self.cleanup_expired()
        return len(self._sessions)
