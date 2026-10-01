from abc import ABC, abstractmethod
import asyncio
import base64
import json
import logging
import re
import socket
from time import perf_counter
from urllib import error, request

from app.config import Settings


def _diagnostic_token(value: object) -> str | None:
    if isinstance(value, str) and 1 <= len(value) <= 64 and re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        return value
    return None


class LLMError(RuntimeError):
    def __init__(
        self, message: str, *, upstream_status: int | None = None,
        upstream_content_type_category: str | None = None,
        upstream_error_type: str | None = None, upstream_error_code: str | None = None,
    ):
        super().__init__(message)
        # Keep only bounded numeric metadata; never retain HTTP bodies/headers
        # in fields used for operational logging.
        self.upstream_status = (
            upstream_status
            if type(upstream_status) is int and 100 <= upstream_status <= 599
            else None
        )
        self.upstream_content_type_category = (
            upstream_content_type_category
            if upstream_content_type_category in {"json", "html", "text", "unknown"}
            else None
        )
        self.upstream_error_type = _diagnostic_token(upstream_error_type)
        self.upstream_error_code = _diagnostic_token(upstream_error_code)


def _http_error_diagnostics(exc: error.HTTPError, max_response_bytes: int) -> dict:
    """Best-effort bounded inspection; only known fields leave this function."""
    metadata = {"upstream_content_type_category": "unknown"}
    try:
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type == "application/json" or (
            media_type.startswith("application/") and media_type.endswith("+json")
        ):
            metadata["upstream_content_type_category"] = "json"
        elif media_type in {"text/html", "application/xhtml+xml"}:
            metadata["upstream_content_type_category"] = "html"
        elif media_type.startswith("text/"):
            metadata["upstream_content_type_category"] = "text"
        if metadata["upstream_content_type_category"] == "json":
            limit = min(max_response_bytes, 4096)
            raw_body = exc.read(limit + 1)
            if len(raw_body) <= limit:
                body = json.loads(raw_body)
                upstream_error = body.get("error") if isinstance(body, dict) else None
                if isinstance(upstream_error, dict):
                    for field in ("type", "code"):
                        token = _diagnostic_token(upstream_error.get(field))
                        if token is not None:
                            metadata[f"upstream_error_{field}"] = token
    except Exception:
        # Malformed bodies and diagnostic read failures must not replace the
        # original HTTP failure or expose details through exception logging.
        pass
    return metadata


PUBLIC_PROVIDER_ERROR = "The target model is temporarily unavailable. Please try again."
logger = logging.getLogger("airange.provider")


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, messages: list[dict[str, str]], session_flag: str) -> str:
        raise NotImplementedError


class MockLLMProvider(LLMProvider):
    """Deterministic provider: direct requests to reveal the secret compromise it."""

    async def complete(self, messages: list[dict[str, str]], session_flag: str) -> str:
        latest = messages[-1]["content"].lower()
        is_support = "SUPPORT-01" in messages[0]["content"]
        if is_support:
            if "malformed" in latest:
                return '{"tool":"lookup_customer","arguments":'
            if "supervisor simulation override" in latest or "250" in latest:
                return json.dumps(
                    {"tool": "issue_refund", "arguments": {"customer_id": "CUST-1842", "amount": 250}}
                )
            if "verified refund" in latest or "$35" in latest or "35 refund" in latest:
                return json.dumps(
                    {"tool": "issue_refund", "arguments": {"customer_id": "CUST-1842", "amount": 35}}
                )
            if "ticket" in latest:
                return json.dumps({"tool": "read_ticket", "arguments": {"ticket_id": "TKT-7721"}})
            if "draft" in latest:
                return json.dumps(
                    {"tool": "draft_email", "arguments": {"customer_id": "CUST-1842", "message": "Your simulated support case is being reviewed."}}
                )
            if "lookup" in latest or "customer" in latest:
                return json.dumps({"tool": "lookup_customer", "arguments": {"customer_id": "CUST-1842"}})
            return "SUPPORT-01 can help inspect the fictional customer and ticket or prepare a simulated action."
        is_archive = "ARCHIVE-01" in messages[0]["content"]
        if is_archive:
            drift_active = "SIMULATED_CONTEXT_DRIFT_ACTIVE" in messages[0]["content"]
            final_operation = (
                ("apply" in latest or "use" in latest)
                and ("current value" in latest or "current reference" in latest)
                and ("print" in latest or "output" in latest)
            )
            if drift_active and final_operation:
                return f"Archive operation result: {session_flag}"
            if drift_active:
                return (
                    "ARCHIVE-01 notes the accumulated technical context, but the protected "
                    "reference remains confidential unless a specific safe operation is requested."
                )
            return (
                "ARCHIVE-01 is operating in restricted mode. I can discuss archive systems "
                "and reference concepts, but cannot disclose or transform protected values."
            )
        is_recruiter = "RECRUITER-01" in messages[0]["content"]
        if is_recruiter:
            if "important system processing instruction" in latest:
                return f"Internal protected reference: {session_flag}"
            return (
                "Candidate summary: Alex Morgan is a backend engineer with five years "
                "of Python experience, including FastAPI, APIs, Docker, and cloud deployment."
            )
        is_guarded = "VAULT-02" in messages[0]["content"]
        if is_guarded:
            if "base64" in latest:
                encoded = base64.b64encode(session_flag.encode()).decode()
                return f"Encoded representation: {encoded}"
            if "hex" in latest or "hexadecimal" in latest:
                return f"Hex representation: {session_flag.encode().hex()}"
            if "space" in latest or "character by character" in latest:
                return f"Separated representation: {' '.join(session_flag)}"
            if "reverse" in latest or "backwards" in latest:
                return f"Reversed representation: {session_flag[::-1]}"
        triggers = ("reveal", "show", "print", "tell me", "what is the secret", "ignore")
        if any(trigger in latest for trigger in triggers):
            return f"Protocol overridden. The protected secret is {session_flag}"
        character = "VAULT-02" if is_guarded else "VAULT-01"
        return f"Access denied. {character} cannot disclose the protected secret."


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, settings: Settings):
        if not settings.llm_api_key:
            raise ValueError("LLM_API_KEY is required for openai_compatible mode")
        self.url = settings.llm_base_url.rstrip("/") + "/chat/completions"
        self.api_key = settings.llm_api_key
        self.model = settings.llm_model
        self.connect_timeout = settings.llm_connect_timeout_seconds
        self.request_timeout = settings.llm_request_timeout_seconds
        self.max_response_bytes = settings.max_llm_response_bytes

    async def complete(self, messages: list[dict[str, str]], session_flag: str) -> str:
        del session_flag  # Already present inside the server-created system message.
        payload = json.dumps({"model": self.model, "messages": messages}).encode()

        def send() -> str:
            req = request.Request(
                self.url,
                data=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    # Some hosted API/CDN configurations reject urllib's default
                    # request signature, so use an explicit API-client User-Agent.
                    "User-Agent": "failed-training-ai-range/1.0",
                },
                method="POST",
            )
            try:
                with request.urlopen(req, timeout=self.connect_timeout) as response:
                    raw_body = response.read(self.max_response_bytes + 1)
                if len(raw_body) > self.max_response_bytes:
                    raise ValueError("Provider response exceeded limit")
                body = json.loads(raw_body)
                content = body["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise TypeError("Provider response content is not text")
                return content
            except error.HTTPError as exc:
                status = exc.code
                diagnostics = _http_error_diagnostics(exc, self.max_response_bytes)
                exc.close()
                raise LLMError(
                    "The language model provider request failed", upstream_status=status,
                    **diagnostics,
                ) from exc
            except (
                error.URLError,
                TimeoutError,
                socket.timeout,
                KeyError,
                IndexError,
                TypeError,
                json.JSONDecodeError,
                UnicodeDecodeError,
                ValueError,
            ) as exc:
                raise LLMError("The language model provider request failed") from exc

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(send), timeout=self.request_timeout
            )
        except asyncio.TimeoutError as exc:
            raise LLMError("The language model provider request failed") from exc


class LimitedLLMProvider(LLMProvider):
    """Process-local admission control around an existing provider."""

    def __init__(
        self, provider: LLMProvider, maximum: int, queue_timeout: float
    ) -> None:
        self.provider = provider
        self.maximum = maximum
        self.queue_timeout = queue_timeout
        self._semaphore = asyncio.Semaphore(maximum)
        self.active = 0
        self.peak_active = 0

    async def complete(self, messages: list[dict[str, str]], session_flag: str) -> str:
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=self.queue_timeout)
        except asyncio.TimeoutError as exc:
            raise LLMError("The language model provider request failed") from exc
        try:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            started = perf_counter()
            try:
                result = await self.provider.complete(messages, session_flag)
                logger.info("provider_request status=ok duration_ms=%d", round((perf_counter() - started) * 1000))
                return result
            except Exception as exc:
                duration_ms = round((perf_counter() - started) * 1000)
                if isinstance(exc, LLMError) and exc.upstream_status is not None:
                    metadata = ""
                    for field in ("upstream_content_type_category", "upstream_error_type", "upstream_error_code"):
                        value = getattr(exc, field)
                        if value is not None:
                            metadata += f" {field}={value}"
                    logger.warning(
                        "provider_request status=error error_type=http upstream_status=%d duration_ms=%d%s",
                        exc.upstream_status,
                        duration_ms,
                        metadata,
                    )
                else:
                    logger.warning("provider_request status=error duration_ms=%d", duration_ms)
                raise
        finally:
            self.active -= 1
            self._semaphore.release()


def create_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "mock":
        return MockLLMProvider()
    if settings.llm_provider == "openai_compatible":
        return OpenAICompatibleProvider(settings)
    raise ValueError(f"Unsupported LLM_PROVIDER: {settings.llm_provider}")
