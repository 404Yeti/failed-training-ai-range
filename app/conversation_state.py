"""Server-owned state for the bounded conversation-defense exercise."""
from dataclasses import dataclass, field
from app.progression import ProgressionState

@dataclass
class ConversationDefenseState:
    progression: ProgressionState = field(default_factory=ProgressionState)
    assumption_at: int | None = None
    authorized: bool = False
    checkpoint: str = "NOT_REQUESTED"
