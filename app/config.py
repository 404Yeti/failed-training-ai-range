from dataclasses import dataclass
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    challenge_dir: Path = BASE_DIR / "challenges"
    document_dir: Path = BASE_DIR / "documents"
    llm_provider: str = os.getenv("LLM_PROVIDER", "mock")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o-mini")
    max_prompt_length: int = int(os.getenv("MAX_PROMPT_LENGTH", "2000"))


settings = Settings()
