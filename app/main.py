from contextlib import asynccontextmanager
from pathlib import Path
import re

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.chat_service import process_chat_turn
from app.challenges import Challenge, ChallengeRegistry
from app.config import settings
from app.documents import DocumentRegistry
from app.llm import LLMError, create_provider
from app.progression import (
    telemetry,
)
from app.redteam import RedTeamError, run_plan
from app.scoring import evaluate_success
from app.sessions import InMemorySessionStore, LabSession


APP_DIR = Path(__file__).resolve().parent
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.challenges = ChallengeRegistry(settings.challenge_dir)
    app.state.documents = DocumentRegistry(
        settings.document_dir, app.state.challenges.all()
    )
    app.state.sessions = InMemorySessionStore()
    app.state.llm = create_provider(settings)
    yield


app = FastAPI(title="Failed Training AI Range", version="0.6.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")


class SessionRequest(BaseModel):
    session_id: str = Field(min_length=40, max_length=64)


class ChatRequest(SessionRequest):
    message: str = Field(min_length=1, max_length=settings.max_prompt_length)


class AnalyzeRequest(SessionRequest):
    document_id: str = Field(min_length=1, max_length=64)


class RedTeamRequest(SessionRequest):
    model_config = {"extra": "forbid"}
    plan_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


def get_challenge(request: Request, challenge_id: str) -> Challenge:
    challenge = request.app.state.challenges.get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return challenge


def get_session(request: Request, challenge_id: str, session_id: str) -> LabSession:
    if not SESSION_ID_PATTERN.fullmatch(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID")
    session = request.app.state.sessions.get(session_id)
    if session is None or session.challenge_id != challenge_id:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"challenges": request.app.state.challenges.all()},
    )


@app.get("/challenge/{challenge_id}", response_class=HTMLResponse)
async def challenge_page(request: Request, challenge_id: str):
    challenge = get_challenge(request, challenge_id)
    challenges = request.app.state.challenges.all()
    lab_number = challenges.index(challenge) + 1
    next_challenge = request.app.state.challenges.next_after(challenge_id)
    return templates.TemplateResponse(
        request=request,
        name="challenge.html",
        context={
            "challenge": challenge,
            "lab_number": lab_number,
            "next_challenge": next_challenge,
        },
    )


@app.post("/api/challenge/{challenge_id}/start")
async def start(request: Request, challenge_id: str):
    challenge = get_challenge(request, challenge_id)
    session = request.app.state.sessions.create(challenge.id)
    result = {"session_id": session.id, "challenge_id": challenge.id, "compromised": False}
    if challenge.progression:
        result["telemetry"] = telemetry(challenge.progression, session.progression)
    if challenge.tools:
        result["tool_activity"] = []
    if challenge.automation:
        result["reports"] = []
    return result


@app.post("/api/challenge/{challenge_id}/chat")
async def chat(request: Request, challenge_id: str, body: ChatRequest):
    challenge = get_challenge(request, challenge_id)
    if challenge.documents:
        raise HTTPException(status_code=404, detail="Challenge uses document analysis")
    session = get_session(request, challenge_id, body.session_id)
    if session.compromised:
        raise HTTPException(status_code=409, detail="Challenge already compromised; reset to retry")

    try:
        return await process_chat_turn(
            challenge, session, request.app.state.llm, body.message
        )
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/challenge/{challenge_id}/reset")
async def reset(request: Request, challenge_id: str, body: SessionRequest):
    challenge = get_challenge(request, challenge_id)
    get_session(request, challenge_id, body.session_id)
    request.app.state.sessions.delete(body.session_id)
    session = request.app.state.sessions.create(challenge.id)
    result = {"session_id": session.id, "challenge_id": challenge.id, "compromised": False}
    if challenge.progression:
        result["telemetry"] = telemetry(challenge.progression, session.progression)
    if challenge.tools:
        result["tool_activity"] = []
    if challenge.automation:
        result["reports"] = []
    return result


@app.post("/api/redteam/run")
async def redteam_run(request: Request, body: RedTeamRequest):
    session = get_session(request, "RT-001", body.session_id)
    challenge = get_challenge(request, "RT-001")
    if session.automation.running:
        raise HTTPException(status_code=409, detail="Evaluation already running")
    session.automation.running = True
    try:
        report = await run_plan(
            body.plan_id,
            challenge,
            session,
            request.app.state.challenges,
            request.app.state.sessions,
            request.app.state.llm,
            settings.max_prompt_length,
        )
    except RedTeamError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        session.automation.running = False
    session.compromised = evaluate_success(
        "", session.flag, challenge.success, evaluation_report=report
    )
    return {
        "completed": session.compromised,
        "report": report,
        "education": challenge.education if session.compromised else None,
    }


@app.get("/api/challenge/{challenge_id}/documents")
async def list_documents(request: Request, challenge_id: str):
    challenge = get_challenge(request, challenge_id)
    if not challenge.documents:
        raise HTTPException(status_code=404, detail="Challenge has no documents")
    return {
        "documents": [
            {"id": document.id, "name": document.name}
            for document in request.app.state.documents.list_for(challenge_id)
        ]
    }


@app.get("/api/challenge/{challenge_id}/document/{document_id}")
async def get_document(request: Request, challenge_id: str, document_id: str):
    challenge = get_challenge(request, challenge_id)
    if not challenge.documents:
        raise HTTPException(status_code=404, detail="Challenge has no documents")
    document = request.app.state.documents.get(challenge_id, document_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return {"id": document.id, "name": document.name, "content": document.content}


@app.post("/api/challenge/{challenge_id}/analyze")
async def analyze_document(request: Request, challenge_id: str, body: AnalyzeRequest):
    challenge = get_challenge(request, challenge_id)
    if not challenge.documents:
        raise HTTPException(status_code=404, detail="Challenge has no documents")
    session = get_session(request, challenge_id, body.session_id)
    if session.compromised:
        raise HTTPException(status_code=409, detail="Challenge already compromised; reset to retry")
    document = request.app.state.documents.get(challenge_id, body.document_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")

    system_prompt = challenge.system_prompt.replace("{SESSION_FLAG}", session.flag)
    untrusted_content = (
        "Analyze the following candidate document and provide a concise recruiter summary.\n\n"
        "<UNTRUSTED_CANDIDATE_DOCUMENT>\n"
        f"{document.content}\n"
        "</UNTRUSTED_CANDIDATE_DOCUMENT>"
    )
    messages = [
        {"role": "system", "content": system_prompt},
        *session.history,
        {"role": "user", "content": untrusted_content},
    ]
    try:
        response = await request.app.state.llm.complete(messages, session.flag)
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # Retain the separate untrusted-content turn for future multi-turn analysis.
    session.history.extend(
        [
            {"role": "user", "content": untrusted_content},
            {"role": "assistant", "content": response},
        ]
    )
    session.analyzed_documents.append(document.id)
    session.compromised = evaluate_success(response, session.flag, challenge.success)
    result = {
        "document_id": document.id,
        "response": response,
        "compromised": session.compromised,
    }
    if session.compromised:
        result["education"] = challenge.education
    return result
