"""Exercise the same proxy middleware and configuration used by Uvicorn."""
import asyncio
from pathlib import Path
import re
from urllib.parse import urlsplit

import httpx
import pytest
from uvicorn import Config
import yaml

from app.config import Settings
from app.main import create_app


@pytest.mark.parametrize(
    "peer,forwarded_proto,expected_scheme",
    [
        ("10.23.4.5", "https", "https"),
        ("203.0.113.9", "https", "http"),
        ("10.23.4.5", None, "http"),
        ("10.23.4.5", "invalid", "http"),
    ],
)
def test_production_proxy_static_urls_and_security(peer, forwarded_proto, expected_scheme):
    hostname = "range.example"
    application = create_app(Settings(
        app_env="production", llm_provider="openai_compatible",
        llm_base_url="https://inference.example/v1", llm_api_key="test-key",
        allowed_hosts=(hostname,),
    ))
    # Example verified ingress subnet for the test, not a claimed Render range.
    server = Config(application, proxy_headers=True, forwarded_allow_ips="10.23.4.0/24")
    server.load()
    headers = {"X-Forwarded-Host": "evil.example", "X-Forwarded-For": "198.51.100.8"}
    if forwarded_proto is not None:
        headers["X-Forwarded-Proto"] = forwarded_proto

    async def scenario():
        async with application.router.lifespan_context(application):
            transport = httpx.ASGITransport(app=server.loaded_app, client=(peer, 12345))
            async with httpx.AsyncClient(transport=transport, base_url=f"http://{hostname}") as client:
                for path in ("/", "/challenge/PI-001", "/challenge/BT-001", "/challenge/BT-002"):
                    page = await client.get(path, headers=headers)
                    assert page.status_code == 200
                    csp = page.headers["Content-Security-Policy"]
                    assert "style-src 'self' 'unsafe-inline'" in csp
                    assert "script-src 'self'" in csp
                    assets = re.findall(r'(?:href|src)="([^"]+/static/[^"]+)"', page.text)
                    assert f"{expected_scheme}://{hostname}/static/style.css" in assets
                    if path != "/":
                        script = "defense.js" if path.endswith(("BT-001", "BT-002")) else "app.js"
                        assert f"{expected_scheme}://{hostname}/static/{script}" in assets
                    for asset in assets:
                        parsed = urlsplit(asset)
                        assert (parsed.scheme, parsed.netloc) == (expected_scheme, hostname)
                        assert (await client.get(asset, headers=headers)).status_code == 200
                health = await client.get("/health", headers=headers)
                assert health.status_code == 200
                assert health.json() == {"status": "ok"}
                assert health.headers["Cache-Control"] == "no-store"
                assert (await client.get("/health", headers={**headers, "Host": "evil.example"})).status_code == 400

    asyncio.run(scenario())


def test_local_uvicorn_default_does_not_trust_remote_forwarded_headers(monkeypatch):
    monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)
    application = create_app(Settings())
    server = Config(application, proxy_headers=True)
    server.load()

    async def scenario():
        async with application.router.lifespan_context(application):
            transport = httpx.ASGITransport(app=server.loaded_app, client=("203.0.113.9", 12345))
            async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as client:
                page = await client.get("/", headers={"X-Forwarded-Proto": "https"})
                assert page.status_code == 200
                assert 'href="http://localhost:8000/static/style.css"' in page.text

    asyncio.run(scenario())


def test_render_requires_operator_supplied_proxy_trust():
    service = yaml.safe_load(Path("render.yaml").read_text())["services"][0]
    variables = {entry["key"]: entry for entry in service["envVars"]}
    assert variables["FORWARDED_ALLOW_IPS"] == {"key": "FORWARDED_ALLOW_IPS", "sync": False}
    assert service["healthCheckPath"] == "/health"
