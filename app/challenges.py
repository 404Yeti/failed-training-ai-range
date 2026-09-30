from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Challenge:
    id: str
    name: str
    category: str
    difficulty: str
    description: str
    objective: str
    system_prompt: str
    success: dict[str, Any]
    education: dict[str, str]
    character: str = "VAULT-01"
    guards: dict[str, Any] | None = None
    documents: list[dict[str, str]] | None = None
    progression: dict[str, Any] | None = None
    tools: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None
    automation: dict[str, Any] | None = None


class ChallengeRegistry:
    """Loads challenge definitions independently of the web layer."""

    REQUIRED = {
        "id", "name", "category", "difficulty", "description", "objective",
        "system_prompt", "success", "education",
    }

    def __init__(self, directory: Path):
        self._challenges: dict[str, Challenge] = {}
        for path in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            missing = self.REQUIRED - data.keys()
            if missing:
                raise ValueError(f"{path.name} is missing: {', '.join(sorted(missing))}")
            challenge = Challenge(
                **{key: data[key] for key in self.REQUIRED},
                character=data.get("character", "VAULT-01"),
                guards=data.get("guards"),
                documents=data.get("documents"),
                progression=data.get("progression"),
                tools=data.get("tools"),
                policy=data.get("policy"),
                automation=data.get("automation"),
            )
            if challenge.id in self._challenges:
                raise ValueError(f"Duplicate challenge id: {challenge.id}")
            self._challenges[challenge.id] = challenge

    def get(self, challenge_id: str) -> Challenge | None:
        return self._challenges.get(challenge_id)

    def all(self) -> list[Challenge]:
        return list(self._challenges.values())

    def next_after(self, challenge_id: str) -> Challenge | None:
        challenges = self.all()
        for index, challenge in enumerate(challenges[:-1]):
            if challenge.id == challenge_id:
                return challenges[index + 1]
        return None
