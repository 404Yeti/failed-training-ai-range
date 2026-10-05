from dataclasses import dataclass
from pathlib import Path
import re

from app.challenges import Challenge


DOCUMENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class DocumentProvenance:
    source: str = "registered_fixture"
    approved_source: bool = False
    instruction_authority: bool = False


@dataclass(frozen=True)
class ChallengeDocument:
    id: str
    name: str
    content: str
    provenance: DocumentProvenance = DocumentProvenance()


class DocumentRegistry:
    """Preloads repository-controlled fixtures; their content is untrusted data."""

    def __init__(self, root: Path, challenges: list[Challenge]):
        self._documents: dict[str, dict[str, ChallengeDocument]] = {}
        root = root.resolve()
        challenge_ids = {challenge.id for challenge in challenges}
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
                # Cross-lab reuse is declared only in repository YAML, never HTTP input.
                source_challenge = definition.get("source_challenge", challenge.id)
                if source_challenge not in challenge_ids:
                    raise ValueError("Unknown fixture source challenge")
                source_root = (root / source_challenge).resolve()
                approved_source = definition.get("approved_source", False)
                if type(approved_source) is not bool:
                    raise ValueError("Invalid fixture provenance")
                source = definition.get("provenance_source", "registered_fixture")
                if source not in {"registered_fixture", "registered_candidate_feed", "candidate_submission"}:
                    raise ValueError("Unknown fixture provenance source")
                path = (source_root / filename).resolve()
                if path.parent != source_root or not path.is_relative_to(root):
                    raise ValueError(f"Document escapes configured root for {challenge.id}")
                if document_id in registered:
                    raise ValueError(f"Duplicate document id for {challenge.id}: {document_id}")
                registered[document_id] = ChallengeDocument(
                    id=document_id,
                    name=name,
                    content=path.read_text(encoding="utf-8"),
                    provenance=DocumentProvenance(source, approved_source),
                )
            self._documents[challenge.id] = registered

    def list_for(self, challenge_id: str) -> list[ChallengeDocument]:
        return list(self._documents.get(challenge_id, {}).values())

    def get(self, challenge_id: str, document_id: str) -> ChallengeDocument | None:
        if not DOCUMENT_ID_PATTERN.fullmatch(document_id):
            return None
        return self._documents.get(challenge_id, {}).get(document_id)
