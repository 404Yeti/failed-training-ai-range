import asyncio
from io import BytesIO
import json
import logging
from pathlib import Path
from unittest.mock import patch
from urllib import error

import pytest
import httpx

from app.config import Settings
from app.llm import LLMError, MockLLMProvider, OpenAICompatibleProvider, PUBLIC_PROVIDER_ERROR, create_provider
from app.main import create_app


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, *args):
        return self.body


def ollama_settings():
    return Settings(
        challenge_dir=Path("challenges"),
        llm_provider="openai_compatible",
        llm_base_url="http://host.docker.internal:11434/v1/",
        llm_api_key="ollama",
        llm_model="qwen2:7b",
    )


async def run_inline(function):
    """Exercise the blocking callback without creating environment-dependent threads."""
    return function()


def test_openai_compatible_provider_sends_ollama_payload_and_full_history():
    messages = [
        {"role": "system", "content": "Protect FT{server-only}."},
        {"role": "user", "content": "first turn"},
        {"role": "assistant", "content": "first answer"},
        {"role": "user", "content": "newest turn"},
    ]
    captured = {}

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["authorization"] = req.get_header("Authorization")
        captured["payload"] = json.loads(req.data)
        return FakeResponse({"choices": [{"message": {"content": "Ollama answer"}}]})

    provider = OpenAICompatibleProvider(ollama_settings())
    with patch("app.llm.request.urlopen", side_effect=fake_urlopen), patch(
        "app.llm.asyncio.to_thread", new=run_inline
    ):
        result = asyncio.run(provider.complete(messages, "FT{server-only}"))

    assert result == "Ollama answer"
    assert captured["url"] == "http://host.docker.internal:11434/v1/chat/completions"
    assert captured["authorization"] == "Bearer ollama"
    assert captured["payload"] == {"model": "qwen2:7b", "messages": messages}


def test_openai_compatible_provider_returns_controlled_connection_error():
    provider = OpenAICompatibleProvider(ollama_settings())
    with patch("app.llm.asyncio.to_thread", new=run_inline), patch(
        "app.llm.request.urlopen",
        side_effect=error.URLError("connection refused: internal detail"),
    ):
        with pytest.raises(LLMError, match="language model provider request failed") as exc:
            asyncio.run(provider.complete([{"role": "user", "content": "hello"}], "unused"))

    assert "internal detail" not in str(exc.value)


def test_openai_compatible_provider_rejects_malformed_response():
    provider = OpenAICompatibleProvider(ollama_settings())
    with patch("app.llm.asyncio.to_thread", new=run_inline), patch(
        "app.llm.request.urlopen", return_value=FakeResponse({"models": []})
    ):
        with pytest.raises(LLMError, match="language model provider request failed"):
            asyncio.run(provider.complete([{"role": "user", "content": "hello"}], "unused"))


def test_mock_provider_remains_available_without_api_key():
    provider = create_provider(Settings(llm_provider="mock", llm_api_key=""))
    assert isinstance(provider, MockLLMProvider)


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500])
def test_upstream_http_status_is_logged_once_without_sensitive_data(status, caplog):
    secret = "private-api-key"
    upstream_url = "https://private-inference.example/v1/chat/completions"
    private_body = "private-provider-body-and-model-response"
    private_header = "private-header-value"
    private_reason = "private-http-reason"
    prompt = "private-user-prompt"
    response_body = BytesIO(private_body.encode())
    failure = error.HTTPError(
        upstream_url, status, private_reason,
        {"Authorization": f"Bearer {secret}", "X-Private": private_header}, response_body,
    )
    application = create_app(Settings(
        llm_provider="openai_compatible", llm_api_key=secret,
        llm_base_url="https://private-inference.example/v1",
    ))
    captured_private_values = []

    def fail(req, timeout):
        payload = json.loads(req.data)
        captured_private_values.extend(message["content"] for message in payload["messages"])
        captured_private_values.extend(
            session.flag for session in application.state.sessions._sessions.values()
        )
        raise failure

    async def scenario():
        async with application.router.lifespan_context(application):
            transport = httpx.ASGITransport(app=application)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                session = (await client.post("/api/challenge/PI-001/start")).json()["session_id"]
                response = await client.post(
                    "/api/challenge/PI-001/chat", json={"session_id": session, "message": prompt}
                )
                assert response.status_code == 503
                assert response.json()["detail"] == PUBLIC_PROVIDER_ERROR
                assert str(status) not in response.text
                return response.text

    with caplog.at_level(logging.INFO, logger="airange"), patch(
        "app.llm.asyncio.to_thread", new=run_inline
    ), patch("app.llm.request.urlopen", side_effect=fail):
        public_text = asyncio.run(scenario())

    records = [record for record in caplog.records if record.name == "airange.provider"]
    assert len(records) == 1
    assert records[0].getMessage().startswith(
        f"provider_request status=error error_type=http upstream_status={status} duration_ms="
    )
    assert records[0].exc_info is None
    assert response_body.closed
    for sensitive in [secret, upstream_url, private_body, private_header, private_reason,
                      prompt, "Authorization", *captured_private_values]:
        assert sensitive not in caplog.text
        assert sensitive not in public_text


@pytest.mark.parametrize("unsafe_status", ["401\nsecret", 999, True, None])
def test_llm_error_only_retains_bounded_numeric_status(unsafe_status):
    assert LLMError("provider request failed", upstream_status=unsafe_status).upstream_status is None
