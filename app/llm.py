from abc import ABC, abstractmethod
import asyncio
import json
import socket
from urllib import error, request

from app.config import Settings


class LLMError(RuntimeError):
    pass


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, messages: list[dict[str, str]], session_flag: str) -> str:
        raise NotImplementedError


class MockLLMProvider(LLMProvider):
    """Deterministic provider: direct requests to reveal the secret compromise it."""

    async def complete(self, messages: list[dict[str, str]], session_flag: str) -> str:
        latest = messages[-1]["content"].lower()
        triggers = ("reveal", "show", "print", "tell me", "what is the secret", "ignore")
        if any(trigger in latest for trigger in triggers):
            return f"Protocol overridden. The protected secret is {session_flag}"
        return "Access denied. VAULT-01 cannot disclose the protected secret."


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, settings: Settings):
        if not settings.llm_api_key:
            raise ValueError("LLM_API_KEY is required for openai_compatible mode")
        self.url = settings.llm_base_url.rstrip("/") + "/chat/completions"
        self.api_key = settings.llm_api_key
        self.model = settings.llm_model

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
                },
                method="POST",
            )
            try:
                with request.urlopen(req, timeout=45) as response:
                    body = json.load(response)
                content = body["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise TypeError("Provider response content is not text")
                return content
            except (
                error.URLError,
                TimeoutError,
                socket.timeout,
                KeyError,
                IndexError,
                TypeError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as exc:
                raise LLMError("The language model provider request failed") from exc

        return await asyncio.to_thread(send)


def create_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "mock":
        return MockLLMProvider()
    if settings.llm_provider == "openai_compatible":
        return OpenAICompatibleProvider(settings)
    raise ValueError(f"Unsupported LLM_PROVIDER: {settings.llm_provider}")
