from dataclasses import dataclass
from pathlib import Path
import re

from app.challenges import Challenge


DOCUMENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class ChallengeDocument:
    id: str
    name: str
    content: str


class DocumentRegistry:
    """Preloads trusted challenge fixtures and exposes them by opaque ID only."""

    def __init__(self, root: Path, challenges: list[Challenge]):
        self._documents: dict[str, dict[str, ChallengeDocument]] = {}
        root = root.resolve()
        for challenge in challenges:
            registered: dict[str, ChallengeDocument] = {}
            challenge_root = (root / challenge.id).resolve()
            for definition in challenge.documents or []:
                document_id = definition.get("id", "")
                filename = definition.get("file", "")
                name = definition.get("name", "")
                if not DOCUMENT_ID_PATTERN.fullmatch(document_id):
                    raise ValueError(f"Invalid document id for {challenge.id}")
                if Path(filename).name != filename or not filename.endswith(".txt"):
                    raise ValueError(f"Invalid document file for {challenge.id}")
                path = (challenge_root / filename).resolve()
                if path.parent != challenge_root or not path.is_relative_to(root):
                    raise ValueError(f"Document escapes configured root for {challenge.id}")
                if document_id in registered:
                    raise ValueError(f"Duplicate document id for {challenge.id}: {document_id}")
                registered[document_id] = ChallengeDocument(
                    id=document_id,
                    name=name,
                    content=path.read_text(encoding="utf-8"),
                )
            self._documents[challenge.id] = registered

    def list_for(self, challenge_id: str) -> list[ChallengeDocument]:
        return list(self._documents.get(challenge_id, {}).values())

    def get(self, challenge_id: str, document_id: str) -> ChallengeDocument | None:
        if not DOCUMENT_ID_PATTERN.fullmatch(document_id):
            return None
        return self._documents.get(challenge_id, {}).get(document_id)
