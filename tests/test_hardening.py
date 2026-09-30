import asyncio
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from unittest.mock import patch

from app.config import ConfigurationError, Settings
from app.llm import (
    LLMError,
    LLMProvider,
    LimitedLLMProvider,
    OpenAICompatibleProvider,
    PUBLIC_PROVIDER_ERROR,
)
from app.main import create_app
from app.rate_limit import InMemoryRateLimiter
from app.sessions import InMemorySessionStore, SessionCapacityError


def dev_settings(**changes):
    base = Settings(
        challenge_dir=Path("challenges"),
        document_dir=Path("documents"),
        app_env="development",
        llm_provider="mock",
        allowed_hosts=("test", "localhost", "127.0.0.1"),
    )
    return replace(base, **changes)


def run_app(app, scenario, base_url="http://test"):
    async def execute():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
                await scenario(client)

    asyncio.run(execute())


def test_development_defaults_and_invalid_environment():
    config = Settings.from_env({})
    assert config.app_env == "development"
    assert config.llm_provider == "mock"
    assert "localhost" in config.allowed_hosts
    with pytest.raises(ConfigurationError, match="APP_ENV"):
        Settings.from_env({"APP_ENV": "staging"})


def test_production_fails_closed_without_hosted_provider_configuration():
    with pytest.raises(ConfigurationError, match="Production requires"):
        Settings.from_env({"APP_ENV": "production", "ALLOWED_HOSTS": "play.failedtraining.com"})
    with pytest.raises(ConfigurationError, match="LLM_API_KEY"):
        Settings.from_env(
            {
                "APP_ENV": "production",
                "ALLOWED_HOSTS": "play.failedtraining.com",
                "LLM_PROVIDER": "openai_compatible",
                "LLM_BASE_URL": "https://inference.example/v1",
                "LLM_MODEL": "hosted-model",
            }
        )


def test_configuration_errors_and_repr_do_not_expose_api_key():
    secret = "production-secret-value"
    config = Settings(
        app_env="production",
        llm_provider="openai_compatible",
        llm_base_url="http://inference.example/v1",
        llm_api_key=secret,
        llm_model="model",
        allowed_hosts=("play.failedtraining.com",),
    )
    assert secret not in repr(config)
    with pytest.raises(ConfigurationError) as exc:
        config.validate()
    assert secret not in str(exc.value)


def test_session_ids_ttl_refresh_cleanup_capacity_and_isolation():
    store = InMemorySessionStore(ttl_minutes=1, max_active_sessions=2)
    first = store.create("PI-001")
    second = store.create("PI-002")
    assert len(first.id) == 43 and first.id != second.id
    assert first.flag != second.flag and first.history is not second.history
    with pytest.raises(SessionCapacityError):
        store.create("II-001")

    prior = first.last_activity
    assert store.get(first.id) is first
    assert first.last_activity >= prior
    first.last_activity -= timedelta(minutes=2)
    assert store.cleanup_expired() == 1
    assert store.get(first.id) is None
    assert store.create("II-001").challenge_id == "II-001"


def test_malformed_session_and_oversized_prompt_and_body_fail_safely():
    application = create_app(dev_settings(max_prompt_length=20, max_request_body_bytes=1024))

    async def scenario(client):
        malformed = await client.post(
            "/api/challenge/PI-001/chat", json={"session_id": "short", "message": "hello"}
        )
        assert malformed.status_code == 422
        started = (await client.post("/api/challenge/PI-001/start")).json()
        prompt = await client.post(
            "/api/challenge/PI-001/chat",
            json={"session_id": started["session_id"], "message": "x" * 21},
        )
        assert prompt.status_code == 422
        oversized = await client.post(
            "/api/challenge/PI-001/start",
            content=b"x" * 1025,
            headers={"Content-Type": "application/json"},
        )
        assert oversized.status_code == 413

    run_app(application, scenario)


def test_chat_rate_limit_returns_429_retry_after_without_affecting_other_session():
    application = create_app(dev_settings(chat_requests_per_minute=1))

    async def scenario(client):
        one = (await client.post("/api/challenge/PI-001/start")).json()["session_id"]
        two = (await client.post("/api/challenge/PI-001/start")).json()["session_id"]
        assert (await client.post("/api/challenge/PI-001/chat", json={"session_id": one, "message": "hello"})).status_code == 200
        limited = await client.post("/api/challenge/PI-001/chat", json={"session_id": one, "message": "again"})
        assert limited.status_code == 429
        assert int(limited.headers["Retry-After"]) >= 1
        assert (await client.post("/api/challenge/PI-001/chat", json={"session_id": two, "message": "hello"})).status_code == 200

    run_app(application, scenario)


def test_automation_rate_limit_and_arbitrary_destination_rejection():
    application = create_app(dev_settings(automation_runs_per_minute=1))

    async def scenario(client):
        session = (await client.post("/api/challenge/RT-001/start")).json()["session_id"]
        first = await client.post("/api/redteam/run", json={"session_id": session, "plan_id": "intro-prompt-injection"})
        assert first.status_code == 200
        limited = await client.post("/api/redteam/run", json={"session_id": session, "plan_id": "intro-prompt-injection"})
        assert limited.status_code == 429
        for field in ("url", "host", "target", "prompts"):
            rejected = await client.post(
                "/api/redteam/run",
                json={"session_id": session, "plan_id": "intro-prompt-injection", field: "https://example.test"},
            )
            assert rejected.status_code == 422

    run_app(application, scenario)


def test_rate_limit_state_expires_deterministically():
    limiter = InMemoryRateLimiter(window_seconds=60)
    assert limiter.check("chat:one", 1, now=0).allowed
    assert not limiter.check("chat:one", 1, now=1).allowed
    assert limiter.cleanup(now=61) == 1
    assert limiter.check("chat:one", 1, now=61).allowed


def test_llm_concurrency_is_bounded():
    class BlockingProvider(LLMProvider):
        def __init__(self):
            self.active = 0
            self.peak = 0

        async def complete(self, messages, session_flag):
            self.active += 1
            self.peak = max(self.peak, self.active)
            await asyncio.sleep(0.01)
            self.active -= 1
            return "ok"

    async def exercise():
        inner = BlockingProvider()
        provider = LimitedLLMProvider(inner, maximum=2, queue_timeout=1)
        await asyncio.gather(
            *(provider.complete([{"role": "user", "content": "x"}], "unused") for _ in range(6))
        )
        assert inner.peak == 2
        assert provider.peak_active == 2

    asyncio.run(exercise())


def test_provider_queue_timeout_is_controlled():
    class SlowProvider(LLMProvider):
        async def complete(self, messages, session_flag):
            await asyncio.sleep(0.05)
            return "ok"

    async def exercise():
        provider = LimitedLLMProvider(SlowProvider(), maximum=1, queue_timeout=0.005)
        first = asyncio.create_task(provider.complete([], "unused"))
        await asyncio.sleep(0)
        with pytest.raises(LLMError, match="provider request failed"):
            await provider.complete([], "unused")
        await first

    asyncio.run(exercise())


def test_provider_total_timeout_is_controlled():
    config = dev_settings(
        llm_provider="openai_compatible",
        llm_api_key="placeholder",
        llm_base_url="https://inference.example/v1",
        llm_request_timeout_seconds=0.001,
    )
    provider = OpenAICompatibleProvider(config)

    async def slow_thread(function):
        del function
        await asyncio.sleep(0.02)

    with patch("app.llm.asyncio.to_thread", new=slow_thread):
        with pytest.raises(LLMError, match="provider request failed"):
            asyncio.run(provider.complete([{"role": "user", "content": "hello"}], "unused"))


def test_provider_error_is_safe_and_upstream_detail_is_not_exposed():
    class FailingProvider:
        async def complete(self, messages, session_flag):
            raise LLMError("upstream https://private.example failed with token secret-token")

    application = create_app(dev_settings())

    async def scenario(client):
        application.state.llm = FailingProvider()
        session = (await client.post("/api/challenge/PI-001/start")).json()["session_id"]
        response = await client.post(
            "/api/challenge/PI-001/chat", json={"session_id": session, "message": "hello"}
        )
        assert response.status_code == 503
        assert response.json()["detail"] == PUBLIC_PROVIDER_ERROR
        assert "private.example" not in response.text and "secret-token" not in response.text

    run_app(application, scenario)


def test_health_request_id_headers_cache_host_origin_and_no_cors():
    application = create_app(dev_settings())

    async def scenario(client):
        health = await client.get("/health", headers={"X-Request-ID": "classroom-123"})
        assert health.status_code == 200 and health.json() == {"status": "ok"}
        assert health.headers["X-Request-ID"] == "classroom-123"
        assert health.headers["Cache-Control"] == "no-store"
        assert health.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in health.headers["Content-Security-Policy"]
        assert "Access-Control-Allow-Origin" not in health.headers
        generated = await client.get("/health", headers={"X-Request-ID": "x" * 1000})
        assert len(generated.headers["X-Request-ID"]) == 32
        cross_origin = await client.post(
            "/api/challenge/PI-001/start", json={}, headers={"Origin": "https://evil.example"}
        )
        assert cross_origin.status_code == 403

    run_app(application, scenario)

    async def invalid_host(client):
        assert (await client.get("/health")).status_code == 400

    run_app(application, invalid_host, base_url="http://evil.example")


def test_health_does_not_call_provider_and_labs_still_start():
    application = create_app(dev_settings())

    class FailIfCalled:
        async def complete(self, messages, session_flag):
            raise AssertionError("health called provider")

    async def scenario(client):
        application.state.llm = FailIfCalled()
        assert (await client.get("/health")).status_code == 200
        for challenge_id in ("PI-001", "PI-002", "II-001", "MT-001", "AG-001", "RT-001"):
            response = await client.post(f"/api/challenge/{challenge_id}/start")
            assert response.status_code == 200
            assert "flag" not in response.text and "system_prompt" not in response.text

    run_app(application, scenario)


def test_production_host_validation_and_public_500_are_safe():
    secret = "not-for-browser"
    config = Settings(
        challenge_dir=Path("challenges"),
        document_dir=Path("documents"),
        app_env="production",
        llm_provider="openai_compatible",
        llm_base_url="https://inference.example/v1",
        llm_api_key=secret,
        llm_model="hosted-model",
        allowed_hosts=("play.failedtraining.com",),
    )
    application = create_app(config)

    @application.get("/test-internal-error")
    async def internal_error():
        raise RuntimeError("private traceback detail")

    async def scenario(client):
        health = await client.get("/health")
        assert health.status_code == 200
        assert secret not in health.text
        failed = await client.get("/test-internal-error")
        assert failed.status_code == 500
        assert failed.json()["detail"] == "Internal server error"
        assert "traceback" not in failed.text.lower()
        assert "private traceback detail" not in failed.text

    run_app(application, scenario, base_url="https://play.failedtraining.com")

    async def wrong_host(client):
        assert (await client.get("/health")).status_code == 400

    run_app(application, wrong_host, base_url="https://wrong.example")


def test_templates_and_javascript_do_not_render_hidden_or_generated_html():
    templates = "\n".join(path.read_text(encoding="utf-8") for path in Path("app/templates").glob("*.html"))
    script = Path("app/static/app.js").read_text(encoding="utf-8")
    assert "|safe" not in templates
    assert "simulation_vulnerability" not in templates
    assert "allowed_targets" not in templates
    assert "system_prompt" not in templates
    assert "content.textContent = text" in script
    assert "analysisOutput.textContent = data.response" in script
    assert "detail.textContent" in script
