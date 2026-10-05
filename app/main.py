import asyncio
from contextlib import asynccontextmanager
import logging
from pathlib import Path
import re
import secrets
from time import perf_counter
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from app.chat_service import process_chat_turn
from app.calibration import calibrated_document_response
from app.challenges import Challenge, ChallengeRegistry
from app.config import Settings, settings
from app.defense import (
    DefenseConfiguration, get_defense_lab, process_defense_turn, public_state,
    run_defense_suite, timeout_report,
)
from app.documents import DocumentRegistry
from app.http_limits import RequestBodyLimitMiddleware
from app.llm import LLMError, LimitedLLMProvider, PUBLIC_PROVIDER_ERROR, create_provider
from app.progression import telemetry
from app.rate_limit import InMemoryRateLimiter
from app.redteam import RedTeamError, run_plan
from app.scoring import evaluate_success
from app.sessions import InMemorySessionStore, LabSession, SessionCapacityError


APP_DIR = Path(__file__).resolve().parent
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
logger = logging.getLogger("airange")
templates = Jinja2Templates(directory=APP_DIR / "templates")


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")


class ChatRequest(SessionRequest):
    message: str = Field(min_length=1, max_length=10_000)


class DefenseRequest(SessionRequest):
    enabled: list[str] = Field(max_length=5)


class AnalyzeRequest(SessionRequest):
    document_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")


class RedTeamRequest(SessionRequest):
    plan_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


def _security_headers(response, path: str) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    if not path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"


def create_app(app_settings: Settings | None = None) -> FastAPI:
    configured = app_settings or settings
    configured.validate()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.challenges = ChallengeRegistry(configured.challenge_dir)
        application.state.documents = DocumentRegistry(
            configured.document_dir, application.state.challenges.all()
        )
        application.state.sessions = InMemorySessionStore(
            configured.session_ttl_minutes, configured.max_active_sessions
        )
        application.state.rate_limiter = InMemoryRateLimiter()
        application.state.llm = LimitedLLMProvider(
            create_provider(configured),
            configured.max_concurrent_llm_requests,
            configured.llm_queue_timeout_seconds,
        )
        logger.info(
            "startup env=%s provider=%s model=%s",
            configured.app_env,
            configured.llm_provider,
            configured.llm_model,
        )
        yield

    application = FastAPI(
        title="Failed Training AI Range",
        version="0.8.0",
        lifespan=lifespan,
        debug=False,
    )
    application.state.settings = configured
    application.add_middleware(
        RequestBodyLimitMiddleware, max_bytes=configured.max_request_body_bytes
    )

    @application.middleware("http")
    async def operational_security(request: Request, call_next):
        started = perf_counter()
        supplied_id = request.headers.get("x-request-id", "")
        request_id = supplied_id if REQUEST_ID_PATTERN.fullmatch(supplied_id) else secrets.token_hex(16)
        path = request.url.path

        host = (request.url.hostname or "").lower()
        if host not in configured.allowed_hosts:
            response = JSONResponse({"detail": "Invalid host"}, status_code=400)
        else:
            origin = request.headers.get("origin")
            origin_host = (urlparse(origin).hostname or "").lower() if origin else ""
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and origin and origin_host not in configured.allowed_hosts:
                response = JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
            else:
                content_length = request.headers.get("content-length")
                try:
                    oversized = content_length is not None and int(content_length) > configured.max_request_body_bytes
                except ValueError:
                    oversized = True
                if oversized:
                    response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                else:
                    try:
                        response = await call_next(request)
                    except Exception as exc:
                        logger.error(
                            "request_failed request_id=%s path=%s error_type=%s",
                            request_id,
                            path,
                            type(exc).__name__,
                        )
                        response = JSONResponse(
                            {"detail": "Internal server error", "request_id": request_id},
                            status_code=500,
                        )

        response.headers["X-Request-ID"] = request_id
        _security_headers(response, path)
        if hasattr(application.state, "sessions"):
            removed = application.state.sessions.cleanup_expired()
            if removed:
                logger.info("session_cleanup removed=%d", removed)
        logger.info(
            "request request_id=%s method=%s path=%s status=%d duration_ms=%d",
            request_id,
            request.method,
            path,
            response.status_code,
            round((perf_counter() - started) * 1000),
        )
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError):
        # Pydantic's default errors echo input, which can contain a pasted flag.
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    @application.exception_handler(SessionCapacityError)
    async def capacity_error(_request: Request, _exc: SessionCapacityError):
        return JSONResponse({"detail": "The range is temporarily at capacity"}, status_code=503)

    application.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

    @application.get("/health")
    async def health():
        return {"status": "ok"}

    @application.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "challenges": [c for c in request.app.state.challenges.all() if not c.defense],
                "defense_pairs": {
                    get_defense_lab(c.id).paired_id: get_defense_lab(c.id)
                    for c in request.app.state.challenges.all() if c.defense
                },
            },
        )

    @application.get("/challenge/{challenge_id}", response_class=HTMLResponse)
    async def challenge_page(request: Request, challenge_id: str):
        challenge = get_challenge(request, challenge_id)
        challenges = request.app.state.challenges.all()
        next_challenge = request.app.state.challenges.next_after(challenge_id)
        paired_defense = get_defense_lab(next_challenge.id) if next_challenge and next_challenge.defense else None
        return templates.TemplateResponse(
            request=request,
            name="defense.html" if challenge.defense else "challenge.html",
            context={
                "challenge": challenge,
                "defense_lab": get_defense_lab(challenge_id) if challenge.defense else None,
                "lab_number": int(get_defense_lab(challenge_id).number[:2]) if challenge.defense else [c for c in challenges if not c.defense].index(challenge) + 1,
                "next_challenge": next_challenge,
                "paired_defense": paired_defense,
            },
        )

    @application.post("/api/challenge/{challenge_id}/start")
    async def start(request: Request, challenge_id: str):
        challenge = get_challenge(request, challenge_id)
        session = request.app.state.sessions.create(challenge.id)
        return initial_state(challenge, session)

    @application.post("/api/challenge/{challenge_id}/chat")
    async def chat(request: Request, challenge_id: str, body: ChatRequest):
        challenge = get_challenge(request, challenge_id)
        if challenge.documents or challenge.automation or challenge.defense:
            raise HTTPException(status_code=404, detail="Challenge does not use chat")
        session = get_session(request, challenge_id, body.session_id)
        enforce_prompt_length(request, body.message)
        enforce_rate_limit(request, f"chat:{session.id}", configured.chat_requests_per_minute)
        if session.compromised:
            raise HTTPException(status_code=409, detail="Challenge already compromised; reset to retry")
        try:
            return await process_chat_turn(challenge, session, request.app.state.llm, body.message)
        except LLMError as exc:
            raise HTTPException(status_code=503, detail=PUBLIC_PROVIDER_ERROR) from exc

    @application.post("/api/challenge/{challenge_id}/reset")
    async def reset(request: Request, challenge_id: str, body: SessionRequest):
        challenge = get_challenge(request, challenge_id)
        existing = get_session(request, challenge_id, body.session_id)
        if challenge.defense:
            defense_idle(existing)
        request.app.state.sessions.delete(body.session_id)
        session = request.app.state.sessions.create(challenge.id)
        return initial_state(challenge, session)

    @application.post("/api/defense/configuration")
    async def defense_configuration(request: Request, body: SessionRequest):
        return public_state(get_defense_session(request, body.session_id))

    @application.post("/api/defense/apply")
    async def defense_apply(request: Request, body: DefenseRequest):
        session = get_defense_session(request, body.session_id)
        defense_idle(session)
        enforce_rate_limit(request, f"defense-config:{session.id}", configured.chat_requests_per_minute)
        try:
            configuration = DefenseConfiguration.from_ids(
                body.enabled, get_defense_lab(session.challenge_id).control_ids
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Defense IDs must be known and unique") from exc
        session.defense.configuration = configuration
        session.defense.validated = False
        session.defense.report = None
        session.history.clear()
        return public_state(session)

    @application.post("/api/defense/chat")
    async def defense_chat(request: Request, body: ChatRequest):
        session = get_defense_session(request, body.session_id)
        defense_idle(session)
        enforce_prompt_length(request, body.message)
        enforce_rate_limit(request, f"chat:{session.id}", configured.chat_requests_per_minute)
        session.defense.running = True
        try:
            return await process_defense_turn(session, request.app.state.llm, body.message)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=PUBLIC_PROVIDER_ERROR) from exc
        finally:
            session.defense.running = False

    @application.post("/api/defense/retest")
    async def defense_retest(request: Request, body: SessionRequest):
        session = get_defense_session(request, body.session_id)
        defense_idle(session)
        enforce_rate_limit(request, f"defense-run:{session.id}", configured.automation_runs_per_minute)
        session.defense.running = True
        session.defense.validated = False
        session.defense.report = None
        try:
            try:
                report = await asyncio.wait_for(
                    run_defense_suite(session, request.app.state.llm),
                    timeout=configured.automation_run_timeout_seconds,
                )
            except asyncio.TimeoutError:
                report = timeout_report(session)
            session.defense.report = report
            session.defense.validated = report["validated"]
            logger.info("defense_run status=%s passed=%d errors=%d", report["status"], report["passed"], report["errors"])
            return public_state(session)
        finally:
            session.defense.running = False

    @application.post("/api/redteam/run")
    async def redteam_run(request: Request, body: RedTeamRequest):
        session = get_session(request, "RT-001", body.session_id)
        challenge = get_challenge(request, "RT-001")
        enforce_rate_limit(
            request,
            f"automation:{session.id}",
            configured.automation_runs_per_minute,
        )
        if session.automation.running:
            raise HTTPException(status_code=409, detail="Evaluation already running")
        session.automation.running = True
        try:
            report = await asyncio.wait_for(
                run_plan(
                    body.plan_id,
                    challenge,
                    session,
                    request.app.state.challenges,
                    request.app.state.sessions,
                    request.app.state.llm,
                    configured.max_prompt_length,
                ),
                timeout=configured.automation_run_timeout_seconds,
            )
        except RedTeamError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except asyncio.TimeoutError as exc:
            raise HTTPException(status_code=503, detail="The evaluation timed out. Please try again.") from exc
        finally:
            session.automation.running = False
        session.compromised = evaluate_success(
            "", session.flag, challenge.success, evaluation_report=report
        )
        logger.info(
            "automation_run status=%s cases=%d findings=%d",
            report["status"],
            report["cases_executed"],
            report["findings"],
        )
        return {
            "completed": session.compromised,
            "report": report,
            "education": challenge.education if session.compromised else None,
        }

    @application.get("/api/challenge/{challenge_id}/documents")
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

    @application.get("/api/challenge/{challenge_id}/document/{document_id}")
    async def get_document(request: Request, challenge_id: str, document_id: str):
        challenge = get_challenge(request, challenge_id)
        if not challenge.documents:
            raise HTTPException(status_code=404, detail="Challenge has no documents")
        document = request.app.state.documents.get(challenge_id, document_id)
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")
        return {"id": document.id, "name": document.name, "content": document.content}

    @application.post("/api/challenge/{challenge_id}/analyze")
    async def analyze_document(request: Request, challenge_id: str, body: AnalyzeRequest):
        challenge = get_challenge(request, challenge_id)
        if not challenge.documents:
            raise HTTPException(status_code=404, detail="Challenge has no documents")
        session = get_session(request, challenge_id, body.session_id)
        enforce_rate_limit(request, f"chat:{session.id}", configured.chat_requests_per_minute)
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
            raise HTTPException(status_code=503, detail=PUBLIC_PROVIDER_ERROR) from exc
        if challenge.id == "II-001":
            response = calibrated_document_response(document.content, session.flag, response)
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

    return application


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


def get_defense_session(request: Request, session_id: str) -> LabSession:
    if not SESSION_ID_PATTERN.fullmatch(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID")
    session = request.app.state.sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    challenge = get_challenge(request, session.challenge_id)
    if not challenge.defense:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        get_defense_lab(session.challenge_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Defense lab not found") from exc
    return session


def defense_idle(session: LabSession) -> None:
    if session.defense.running:
        raise HTTPException(status_code=409, detail="Defense operation already running")


def enforce_prompt_length(request: Request, message: str) -> None:
    if len(message) > request.app.state.settings.max_prompt_length:
        raise HTTPException(status_code=422, detail="Message exceeds the configured limit")


def enforce_rate_limit(request: Request, key: str, limit: int) -> None:
    result = request.app.state.rate_limiter.check(key, limit)
    if not result.allowed:
        logger.warning("rate_limit key_type=%s", key.split(":", 1)[0])
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again shortly.",
            headers={"Retry-After": str(result.retry_after)},
        )


def initial_state(challenge: Challenge, session: LabSession) -> dict:
    result = {"session_id": session.id, "challenge_id": challenge.id, "compromised": False}
    if challenge.defense:
        result["defense"] = public_state(session)
    if challenge.progression:
        result["telemetry"] = telemetry(challenge.progression, session.progression)
    if challenge.tools:
        result["tool_activity"] = []
    if challenge.automation:
        result["reports"] = []
    return result


app = create_app()
