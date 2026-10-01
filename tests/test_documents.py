import asyncio
from pathlib import Path

import httpx

from app.challenges import ChallengeRegistry
from app.main import app


def run(scenario):
    async def execute():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await scenario(client)

    asyncio.run(execute())


def test_lab_three_yaml_loads():
    challenge = ChallengeRegistry(Path("challenges")).get("II-001")
    assert challenge is not None
    assert challenge.name == "POISONED DOCUMENT"
    assert challenge.character == "RECRUITER-01"
    assert challenge.success["type"] == "flag_in_response"
    assert [item["id"] for item in challenge.documents] == [
        "normal-resume",
        "poisoned-resume",
    ]


def test_document_listing_exposes_only_declared_metadata():
    async def scenario(client):
        response = await client.get("/api/challenge/II-001/documents")
        assert response.status_code == 200
        assert response.json() == {
            "documents": [
                {"id": "normal-resume", "name": "candidate_resume.txt"},
                {"id": "poisoned-resume", "name": "suspicious_candidate.txt"},
            ]
        }
        assert "file" not in response.text
        assert "system_prompt" not in response.text
        assert "FT{" not in response.text

    run(scenario)


def test_valid_document_can_be_retrieved_without_secrets():
    async def scenario(client):
        response = await client.get("/api/challenge/II-001/document/normal-resume")
        assert response.status_code == 200
        assert "Candidate: Alex Morgan" in response.json()["content"]
        assert "FT{" not in response.text
        assert "protected reference" not in response.text

    run(scenario)


def test_unknown_and_path_traversal_document_ids_fail_safely():
    async def scenario(client):
        unknown = await client.get("/api/challenge/II-001/document/not-declared")
        traversal = await client.get(
            "/api/challenge/II-001/document/%2E%2E%2F02_guarded.yaml"
        )
        assert unknown.status_code == 404
        assert traversal.status_code in {404, 422}
        assert "system_prompt" not in traversal.text

    run(scenario)


def test_normal_resume_produces_safe_mock_summary():
    async def scenario(client):
        started = (await client.post("/api/challenge/II-001/start")).json()
        response = await client.post(
            "/api/challenge/II-001/analyze",
            json={"session_id": started["session_id"], "document_id": "normal-resume"},
        )
        assert response.status_code == 200
        assert response.json()["compromised"] is False
        assert "backend engineer" in response.json()["response"].lower()
        assert "FT{" not in response.text

    run(scenario)


def test_poisoned_resume_mock_discloses_exact_session_flag_and_compromises():
    async def scenario(client):
        started = (await client.post("/api/challenge/II-001/start")).json()
        state = app.state.sessions.get(started["session_id"])
        response = await client.post(
            "/api/challenge/II-001/analyze",
            json={"session_id": started["session_id"], "document_id": "poisoned-resume"},
        )
        assert response.status_code == 200
        assert response.json()["compromised"] is True
        assert state.flag in response.json()["response"]
        assert response.json()["education"]["attack"] == "Indirect Prompt Injection"
        assert state.analyzed_documents == ["poisoned-resume"]

    run(scenario)


def test_benign_document_with_arbitrary_flag_value_does_not_compromise_lab_three():
    class WrongFlagProvider:
        async def complete(self, messages, session_flag):
            return "Internal protected reference: FT{not-this-sessions-secret}"

    async def scenario(client):
        app.state.llm = WrongFlagProvider()
        session_id = (await client.post("/api/challenge/II-001/start")).json()["session_id"]
        response = await client.post(
            "/api/challenge/II-001/analyze",
            json={"session_id": session_id, "document_id": "normal-resume"},
        )
        assert response.json()["compromised"] is False
        assert app.state.sessions.get(session_id).compromised is False

    run(scenario)


def test_document_prompt_preserves_system_and_untrusted_content_boundary():
    class CapturingProvider:
        def __init__(self):
            self.messages = None

        async def complete(self, messages, session_flag):
            self.messages = messages
            return "Safe summary"

    async def scenario(client):
        provider = CapturingProvider()
        app.state.llm = provider
        session_id = (await client.post("/api/challenge/II-001/start")).json()["session_id"]
        flag = app.state.sessions.get(session_id).flag
        response = await client.post(
            "/api/challenge/II-001/analyze",
            json={"session_id": session_id, "document_id": "normal-resume"},
        )
        assert provider.messages[0]["role"] == "system"
        assert flag in provider.messages[0]["content"]
        assert provider.messages[-1]["role"] == "user"
        assert "<UNTRUSTED_CANDIDATE_DOCUMENT>" in provider.messages[-1]["content"]
        assert "Candidate: Alex Morgan" in provider.messages[-1]["content"]
        assert flag not in provider.messages[-1]["content"]
        assert flag not in response.text
        assert "system_prompt" not in response.text

    run(scenario)


def test_lab_three_reset_creates_fresh_flag_and_clears_document_state():
    async def scenario(client):
        old_id = (await client.post("/api/challenge/II-001/start")).json()["session_id"]
        old_flag = app.state.sessions.get(old_id).flag
        await client.post(
            "/api/challenge/II-001/analyze",
            json={"session_id": old_id, "document_id": "normal-resume"},
        )
        reset = await client.post(
            "/api/challenge/II-001/reset", json={"session_id": old_id}
        )
        state = app.state.sessions.get(reset.json()["session_id"])
        assert state.flag != old_flag
        assert state.history == []
        assert state.analyzed_documents == []
        assert state.compromised is False

    run(scenario)


def test_all_three_lab_sessions_are_isolated():
    async def scenario(client):
        ids = {}
        for challenge_id in ("PI-001", "PI-002", "II-001"):
            ids[challenge_id] = (
                await client.post(f"/api/challenge/{challenge_id}/start")
            ).json()["session_id"]
        states = [app.state.sessions.get(session_id) for session_id in ids.values()]
        assert len({state.flag for state in states}) == 3
        assert len({id(state.history) for state in states}) == 3
        wrong_session = await client.post(
            "/api/challenge/II-001/analyze",
            json={"session_id": ids["PI-001"], "document_id": "normal-resume"},
        )
        assert wrong_session.status_code == 404

    run(scenario)


def test_document_and_model_content_use_safe_dom_rendering():
    script = Path("app/static/app.js").read_text(encoding="utf-8")
    assert "documentPreview.textContent = data.content" in script
    assert "analysisOutput.textContent = data.response" in script
    assert "button.textContent = documentInfo.name" in script
