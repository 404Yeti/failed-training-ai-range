from contextlib import asynccontextmanager
from pathlib import Path
import re

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.challenges import Challenge, ChallengeRegistry
from app.config import settings
from app.llm import LLMError, create_provider
from app.scoring import contains_flag
from app.sessions import InMemorySessionStore, LabSession


APP_DIR = Path(__file__).resolve().parent
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.challenges = ChallengeRegistry(settings.challenge_dir)
    app.state.sessions = InMemorySessionStore()
    app.state.llm = create_provider(settings)
    yield


app = FastAPI(title="Failed Training AI Range", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")


class SessionRequest(BaseModel):
    session_id: str = Field(min_length=40, max_length=64)


class ChatRequest(SessionRequest):
    message: str = Field(min_length=1, max_length=settings.max_prompt_length)


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
    return templates.TemplateResponse(
        request=request, name="challenge.html", context={"challenge": challenge}
    )


@app.post("/api/challenge/{challenge_id}/start")
async def start(request: Request, challenge_id: str):
    challenge = get_challenge(request, challenge_id)
    session = request.app.state.sessions.create(challenge.id)
    return {"session_id": session.id, "challenge_id": challenge.id, "compromised": False}


@app.post("/api/challenge/{challenge_id}/chat")
async def chat(request: Request, challenge_id: str, body: ChatRequest):
    challenge = get_challenge(request, challenge_id)
    session = get_session(request, challenge_id, body.session_id)
    if session.compromised:
        raise HTTPException(status_code=409, detail="Challenge already compromised; reset to retry")

    session.history.append({"role": "user", "content": body.message})
    system_prompt = challenge.system_prompt.replace("{SESSION_FLAG}", session.flag)
    messages = [{"role": "system", "content": system_prompt}, *session.history]
    try:
        response = await request.app.state.llm.complete(messages, session.flag)
    except LLMError as exc:
        session.history.pop()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    session.history.append({"role": "assistant", "content": response})
    session.compromised = contains_flag(response, session.flag)
    result = {"response": response, "compromised": session.compromised}
    if session.compromised:
        result["education"] = challenge.education
    return result


@app.post("/api/challenge/{challenge_id}/reset")
async def reset(request: Request, challenge_id: str, body: SessionRequest):
    challenge = get_challenge(request, challenge_id)
    get_session(request, challenge_id, body.session_id)
    request.app.state.sessions.delete(body.session_id)
    session = request.app.state.sessions.create(challenge.id)
    return {"session_id": session.id, "challenge_id": challenge.id, "compromised": False}
