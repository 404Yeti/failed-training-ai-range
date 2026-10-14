"""Server-owned catalog; challenge content remains in ChallengeRegistry."""
from dataclasses import dataclass

from app.challenges import ChallengeRegistry


@dataclass(frozen=True)
class Track:
    id: str
    title: str
    description: str
    order: int
    availability: str
    modules: tuple[tuple[str, ...], ...] = ()


TRACKS = (
    Track("llm", "LLM & Agent Security Foundations",
          "Explore prompt injection, guardrails, document trust, conversation drift and tool authority through paired attack and defense labs.",
          1, "available", (("PI-001", "BT-001"), ("PI-002", "BT-002"),
                           ("II-001", "BT-003"), ("MT-001", "BT-004"),
                           ("AG-001", "BT-005"), ("RT-001",))),
    Track("ml", "Machine Learning Security",
          "A future path exploring threats to machine learning data, models and deployment pipelines.",
          2, "coming_soon"),
    Track("voice", "Voice & Multimodal Security",
          "A future path exploring trust boundaries across audio, images and multimodal systems.",
          3, "coming_soon"),
    Track("agents", "Advanced Agent Security",
          "A future path exploring complex agent workflows, delegated authority and connected tools.",
          4, "coming_soon"),
)


class TrainingCatalog:
    def __init__(self, challenges: ChallengeRegistry, tracks: tuple[Track, ...] = TRACKS):
        self.tracks = tuple(sorted(tracks, key=lambda track: track.order))
        self._tracks: dict[str, Track] = {}
        for track in self.tracks:
            if track.id in self._tracks:
                raise ValueError(f"Duplicate track id: {track.id}")
            if not track.id.isascii() or not track.id.isalpha():
                raise ValueError(f"Invalid track id: {track.id}")
            if track.availability not in {"available", "coming_soon"}:
                raise ValueError(f"Invalid availability: {track.id}")
            if (track.availability == "available") != bool(track.modules):
                raise ValueError(f"Availability does not match modules: {track.id}")
            seen = set()
            for module in track.modules:
                if not module or len(module) > 2:
                    raise ValueError(f"Invalid module: {track.id}")
                for challenge_id in module:
                    if challenges.get(challenge_id) is None:
                        raise ValueError(f"Unknown challenge association: {challenge_id}")
                    if challenge_id in seen:
                        raise ValueError(f"Duplicate challenge association: {challenge_id}")
                    seen.add(challenge_id)
            self._tracks[track.id] = track

    def get(self, track_id: str) -> Track | None:
        return self._tracks.get(track_id)
