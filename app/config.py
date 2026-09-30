from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent.parent


class ConfigurationError(ValueError):
    """Raised for invalid startup configuration without including secret values."""


def _integer(env: dict[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(env.get(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _number(
    env: dict[str, str], name: str, default: float, minimum: float, maximum: float
) -> float:
    try:
        value = float(env.get(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    challenge_dir: Path = BASE_DIR / "challenges"
    document_dir: Path = BASE_DIR / "documents"
    app_env: str = "development"
    llm_provider: str = "mock"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = field(default="", repr=False)
    llm_model: str = "gpt-4o-mini"
    max_prompt_length: int = 2000
    max_request_body_bytes: int = 16_384
    session_ttl_minutes: int = 60
    max_active_sessions: int = 500
    chat_requests_per_minute: int = 20
    automation_runs_per_minute: int = 3
    max_concurrent_llm_requests: int = 8
    llm_queue_timeout_seconds: float = 5.0
    llm_connect_timeout_seconds: float = 45.0
    llm_request_timeout_seconds: float = 45.0
    max_llm_response_bytes: int = 65_536
    automation_run_timeout_seconds: float = 180.0
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "test")

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)
        app_env = env.get("APP_ENV", "development").strip().lower()
        if app_env not in {"development", "production"}:
            raise ConfigurationError("APP_ENV must be development or production")
        default_hosts = "play.failedtraining.com" if app_env == "production" else "localhost,127.0.0.1,test"
        hosts = tuple(
            item.strip().lower()
            for item in env.get("ALLOWED_HOSTS", default_hosts).split(",")
            if item.strip()
        )
        settings = cls(
            app_env=app_env,
            llm_provider=env.get("LLM_PROVIDER", "mock").strip().lower(),
            llm_base_url=env.get("LLM_BASE_URL", "https://api.openai.com/v1").strip(),
            llm_api_key=env.get("LLM_API_KEY", ""),
            llm_model=env.get("LLM_MODEL", "gpt-4o-mini").strip(),
            max_prompt_length=_integer(env, "MAX_PROMPT_LENGTH", 2000, 1, 10_000),
            max_request_body_bytes=_integer(env, "MAX_REQUEST_BODY_BYTES", 16_384, 1024, 1_048_576),
            session_ttl_minutes=_integer(env, "SESSION_TTL_MINUTES", 60, 1, 1440),
            max_active_sessions=_integer(env, "MAX_ACTIVE_SESSIONS", 500, 1, 100_000),
            chat_requests_per_minute=_integer(env, "CHAT_REQUESTS_PER_MINUTE", 20, 1, 1000),
            automation_runs_per_minute=_integer(env, "AUTOMATION_RUNS_PER_MINUTE", 3, 1, 100),
            max_concurrent_llm_requests=_integer(env, "MAX_CONCURRENT_LLM_REQUESTS", 8, 1, 100),
            llm_queue_timeout_seconds=_number(env, "LLM_QUEUE_TIMEOUT_SECONDS", 5, 0.1, 120),
            llm_connect_timeout_seconds=_number(env, "LLM_CONNECT_TIMEOUT_SECONDS", 10, 0.1, 120),
            llm_request_timeout_seconds=_number(env, "LLM_REQUEST_TIMEOUT_SECONDS", 45, 1, 300),
            max_llm_response_bytes=_integer(env, "MAX_LLM_RESPONSE_BYTES", 65_536, 1024, 1_048_576),
            automation_run_timeout_seconds=_number(env, "AUTOMATION_RUN_TIMEOUT_SECONDS", 180, 1, 900),
            allowed_hosts=hosts,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.app_env not in {"development", "production"}:
            raise ConfigurationError("APP_ENV must be development or production")
        if self.llm_provider not in {"mock", "openai_compatible"}:
            raise ConfigurationError("LLM_PROVIDER must be mock or openai_compatible")
        if not self.allowed_hosts or any(
            host == "*"
            or len(host) > 253
            or not re.fullmatch(r"[a-z0-9.-]+", host)
            or host.startswith(".")
            or host.endswith(".")
            for host in self.allowed_hosts
        ):
            raise ConfigurationError("ALLOWED_HOSTS must contain bounded explicit hostnames")
        if self.llm_provider == "openai_compatible":
            parsed = urlparse(self.llm_base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ConfigurationError("LLM_BASE_URL must be an HTTP(S) URL")
            if parsed.username or parsed.password:
                raise ConfigurationError("LLM_BASE_URL must not contain credentials")
            if not self.llm_api_key:
                raise ConfigurationError("LLM_API_KEY is required for openai_compatible mode")
            if not self.llm_model:
                raise ConfigurationError("LLM_MODEL is required for openai_compatible mode")
        if self.app_env == "production":
            if self.llm_provider != "openai_compatible":
                raise ConfigurationError("Production requires LLM_PROVIDER=openai_compatible")
            if urlparse(self.llm_base_url).scheme != "https":
                raise ConfigurationError("Production LLM_BASE_URL must use HTTPS")
            if any(host in {"localhost", "127.0.0.1", "test"} for host in self.allowed_hosts):
                raise ConfigurationError("Production ALLOWED_HOSTS must use public service hostnames")


settings = Settings.from_env()
