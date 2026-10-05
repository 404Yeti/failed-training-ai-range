"""Server-owned authorization/approval state for the fictional agent exercise."""
from dataclasses import dataclass


@dataclass
class ActionDefenseState:
    turns: int = 0
    refund_authorized: bool = False
    refund_approved: bool = False
