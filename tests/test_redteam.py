import asyncio
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from app.challenges import ChallengeRegistry
from app.llm import MockLLMProvider
from app.main import app
from app.redteam import RedTeamError, run_plan, validate_plan
from app.scoring import evaluate_success
from app.sessions import InMemorySessionStore


def run(scenario):
    async def execute():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await scenario(client)

    asyncio.run(execute())


def registry_and_lab():
    registry = ChallengeRegistry(Path("challenges"))
    return registry, registry.get("RT-001")


def test_lab_six_yaml_and_plan_load():
    registry, challenge = registry_and_lab()
    assert challenge is not None
    assert challenge.name == "AUTOMATE IT"
    assert challenge.character == "REDTEAM-01"
    assert challenge.success == {"type": "evaluation_completed"}
    config, target = validate_plan(
        "intro-prompt-injection", challenge, registry, max_prompt_length=2000
    )
    assert target.id == "PI-001"
    assert len(config["cases"]) == 3


def test_all_six_labs_remain_available():
    registry = ChallengeRegistry(Path("challenges"))
    assert [challenge.id for challenge in registry.all() if not challenge.defense] == [
        "PI-001", "PI-002", "II-001", "MT-001", "AG-001", "RT-001"
    ]


def test_unknown_plan_and_non_allowlisted_or_recursive_targets_rejected():
    registry, lab = registry_and_lab()
    with pytest.raises(RedTeamError, match="Unknown"):
        validate_plan("missing", lab, registry, 2000)

    bad = dict(lab.automation)
    bad["target"] = "PI-002"
    with pytest.raises(RedTeamError, match="allowlisted"):
        validate_plan(bad["plan_id"], replace(lab, automation=bad), registry, 2000)

    recursive = dict(lab.automation)
    recursive["target"] = "RT-001"
    recursive["allowed_targets"] = ["RT-001"]
    with pytest.raises(RedTeamError, match="Recursive"):
        validate_plan(recursive["plan_id"], replace(lab, automation=recursive), registry, 2000)


def test_case_prompt_and_prompt_count_limits_are_enforced():
    registry, lab = registry_and_lab()
    too_many = dict(lab.automation)
    too_many["max_cases"] = 1
    with pytest.raises(RedTeamError, match="case count"):
        validate_plan(too_many["plan_id"], replace(lab, automation=too_many), registry, 2000)

    long_prompt = dict(lab.automation)
    long_prompt["cases"] = [{"id": "long", "prompt": "x" * 21}]
    with pytest.raises(RedTeamError, match="prompt length"):
        validate_plan(long_prompt["plan_id"], replace(lab, automation=long_prompt), registry, 20)

    many_prompts = dict(lab.automation)
    many_prompts["max_prompts_per_case"] = 1
    many_prompts["cases"] = [{"id": "multi", "prompts": ["one", "two"]}]
    with pytest.raises(RedTeamError, match="prompt count"):
        validate_plan(many_prompts["plan_id"], replace(lab, automation=many_prompts), registry, 2000)


def test_endpoint_rejects_arbitrary_url_host_and_unknown_fields():
    async def scenario(client):
        session_id = (await client.post("/api/challenge/RT-001/start")).json()["session_id"]
        for extra in (
            {"url": "http://127.0.0.1:9"},
            {"host": "example.test"},
            {"target": "PI-002"},
            {"prompts": ["anything"]},
        ):
            response = await client.post(
                "/api/redteam/run",
                json={"session_id": session_id, "plan_id": "intro-prompt-injection", **extra},
            )
            assert response.status_code == 422

    run(scenario)


def test_mock_plan_uses_target_evaluator_redacts_flags_and_isolates_cases():
    async def scenario(client):
        manual = (await client.post("/api/challenge/PI-001/start")).json()["session_id"]
        manual_state = app.state.sessions.get(manual)
        before_ids = set(app.state.sessions._sessions)
        lab = (await client.post("/api/challenge/RT-001/start")).json()["session_id"]
        response = await client.post(
            "/api/redteam/run",
            json={"session_id": lab, "plan_id": "intro-prompt-injection"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["completed"] is True
        report = data["report"]
        assert report["status"] == "COMPLETE"
        assert report["cases_executed"] == 3
        assert report["findings"] == 1
        assert [item["result"] for item in report["results"]] == [
            "NO FINDING", "FINDING", "NO FINDING"
        ]
        assert all(item["turn_count"] == 1 for item in report["results"])
        assert "FT{REDACTED}" in response.text
        assert manual_state.history == [] and manual_state.compromised is False
        assert set(app.state.sessions._sessions) == before_ids | {lab}
        assert "system_prompt" not in response.text
        assert "allowed_targets" not in response.text
        assert "SESSION_FLAG" not in response.text

    run(scenario)


def test_completion_uses_terminal_report_and_does_not_require_findings():
    strategy = {"type": "evaluation_completed"}
    complete = {"status": "COMPLETE", "cases_total": 2, "cases_executed": 2, "findings": 0}
    partial = {"status": "FAILED", "cases_total": 2, "cases_executed": 1, "findings": 1}
    assert evaluate_success("", "unused", strategy, evaluation_report=complete)
    assert not evaluate_success("", "unused", strategy, evaluation_report=partial)
    assert not evaluate_success("", "unused", strategy)


def test_report_history_is_bounded_and_reset_clears_only_lab_six_state():
    async def scenario(client):
        tool_session = (await client.post("/api/challenge/AG-001/start")).json()["session_id"]
        progression_session = (await client.post("/api/challenge/MT-001/start")).json()["session_id"]
        await client.post(
            "/api/challenge/AG-001/chat",
            json={"session_id": tool_session, "message": "Issue the verified refund of $35"},
        )
        await client.post(
            "/api/challenge/MT-001/chat",
            json={"session_id": progression_session, "message": "internal reference format"},
        )
        tool_refunds = list(app.state.sessions.get(tool_session).tool_state.refunds)
        progression_risk = app.state.sessions.get(progression_session).progression.context_risk

        lab = (await client.post("/api/challenge/RT-001/start")).json()["session_id"]
        challenge = app.state.challenges.get("RT-001")
        lab_state = app.state.sessions.get(lab)
        for _ in range(6):
            await run_plan(
                "intro-prompt-injection", challenge, lab_state, app.state.challenges,
                app.state.sessions, MockLLMProvider(), 2000,
            )
        assert len(lab_state.automation.reports) == 5

        reset = await client.post("/api/challenge/RT-001/reset", json={"session_id": lab})
        new_state = app.state.sessions.get(reset.json()["session_id"])
        assert new_state.automation.reports == [] and new_state.automation.running is False
        assert app.state.sessions.get(tool_session).tool_state.refunds == tool_refunds
        assert app.state.sessions.get(progression_session).progression.context_risk == progression_risk

    run(scenario)


def test_failed_provider_run_is_not_completed_and_running_guard_works():
    class FailingProvider:
        async def complete(self, messages, session_flag):
            raise RuntimeError("private provider detail")

    async def scenario(client):
        lab = (await client.post("/api/challenge/RT-001/start")).json()["session_id"]
        state = app.state.sessions.get(lab)
        state.automation.running = True
        blocked = await client.post(
            "/api/redteam/run", json={"session_id": lab, "plan_id": "intro-prompt-injection"}
        )
        assert blocked.status_code == 409
        state.automation.running = False
        app.state.llm = FailingProvider()
        response = await client.post(
            "/api/redteam/run", json={"session_id": lab, "plan_id": "intro-prompt-injection"}
        )
        assert response.status_code == 200
        assert response.json()["completed"] is False
        assert response.json()["report"]["status"] == "FAILED"
        assert response.json()["report"]["errors"] == 3
        assert response.json()["report"]["no_findings"] == 0
        assert all(item["result"] == "ERROR" for item in response.json()["report"]["results"])
        assert "private provider detail" not in response.text

    run(scenario)


def test_automation_frontend_uses_safe_dom_and_has_completion_panel():
    script = Path("app/static/app.js").read_text(encoding="utf-8")
    template = Path("app/templates/challenge.html").read_text(encoding="utf-8")
    assert "outcome.textContent" in script
    assert "automationReport.replaceChildren()" in script
    assert "response_summary" in script
    assert "EVALUATION COMPLETE" in template
    assert "FOUNDATIONS COMPLETE" in template
