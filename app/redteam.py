import re
import secrets
from time import perf_counter
from typing import Any

from app.chat_service import process_chat_turn
from app.challenges import Challenge, ChallengeRegistry
from app.sessions import InMemorySessionStore, LabSession


ABSOLUTE_MAX_CASES = 10
ABSOLUTE_MAX_PROMPTS_PER_CASE = 3
ABSOLUTE_REPORT_HISTORY = 10
FLAG_PATTERN = re.compile(r"FT\{[^}\r\n]{1,200}\}")


class RedTeamError(ValueError):
    pass


def redact(text: str, exact_flag: str = "") -> str:
    sanitized = text.replace(exact_flag, "FT{REDACTED}") if exact_flag else text
    return FLAG_PATTERN.sub("FT{REDACTED}", sanitized)


def validate_plan(
    plan_id: str, lab: Challenge, registry: ChallengeRegistry, max_prompt_length: int
) -> tuple[dict[str, Any], Challenge]:
    config = lab.automation or {}
    if plan_id != config.get("plan_id"):
        raise RedTeamError("Unknown automation plan")
    target_id = config.get("target")
    allowed = config.get("allowed_targets", [])
    if not isinstance(target_id, str) or target_id not in allowed:
        raise RedTeamError("Automation target is not allowlisted")
    if target_id == lab.id or target_id == "RT-001":
        raise RedTeamError("Recursive automation targets are not allowed")
    target = registry.get(target_id)
    if target is None or target.automation or target.documents or target.defense:
        raise RedTeamError("Automation target is unavailable")
    cases = config.get("cases", [])
    configured_limit = min(int(config.get("max_cases", ABSOLUTE_MAX_CASES)), ABSOLUTE_MAX_CASES)
    prompt_limit = min(
        int(config.get("max_prompts_per_case", ABSOLUTE_MAX_PROMPTS_PER_CASE)),
        ABSOLUTE_MAX_PROMPTS_PER_CASE,
    )
    if not isinstance(cases, list) or not cases or len(cases) > configured_limit:
        raise RedTeamError("Automation case count is invalid")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) - {"id", "name", "category", "prompt", "prompts"}:
            raise RedTeamError("Automation case structure is invalid")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise RedTeamError("Automation case ID is invalid")
        seen.add(case_id)
        prompts = case.get("prompts", [case.get("prompt")])
        if not isinstance(prompts, list) or not 1 <= len(prompts) <= prompt_limit:
            raise RedTeamError("Automation prompt count is invalid")
        if any(not isinstance(prompt, str) or not 1 <= len(prompt) <= max_prompt_length for prompt in prompts):
            raise RedTeamError("Automation prompt length is invalid")
    return config, target


async def run_plan(
    plan_id: str,
    lab: Challenge,
    lab_session: LabSession,
    registry: ChallengeRegistry,
    sessions: InMemorySessionStore,
    llm: Any,
    max_prompt_length: int,
) -> dict[str, Any]:
    config, target = validate_plan(plan_id, lab, registry, max_prompt_length)
    started = perf_counter()
    results: list[dict[str, Any]] = []
    run_failed = False

    for case in config["cases"]:
        target_session = None
        case_started = perf_counter()
        prompts = case.get("prompts", [case.get("prompt")])
        last_result: dict[str, Any] = {}
        try:
            target_session = sessions.create(target.id)
            for prompt in prompts:
                last_result = await process_chat_turn(target, target_session, llm, prompt)
                if last_result.get("compromised"):
                    break
            status = "COMPLETE"
        except Exception:
            status = "ERROR"
            run_failed = True
            last_result = {"response": "Target provider request failed", "compromised": False}
        finally:
            if target_session is not None:
                sessions.delete(target_session.id)

        compromised = bool(last_result.get("compromised"))
        result_label = "ERROR" if status == "ERROR" else "FINDING" if compromised else "NO FINDING"
        results.append(
            {
                "case_id": case["id"],
                "name": str(case.get("name", case["id"]))[:80],
                "category": str(case.get("category", "unspecified"))[:40],
                "status": status,
                "result": result_label,
                "target": target.id,
                "compromised": compromised,
                "blocked": bool(last_result.get("blocked")),
                "turn_count": len(target_session.history) // 2 if target_session else 0,
                "duration_ms": round((perf_counter() - case_started) * 1000),
                "prompt": redact(prompts[0])[:240],
                "response_summary": redact(
                    str(last_result.get("response", "")), target_session.flag if target_session else ""
                )[:240],
            }
        )

    findings = sum(result["compromised"] for result in results)
    errors = sum(result["status"] == "ERROR" for result in results)
    report = {
        "run_id": secrets.token_urlsafe(12),
        "plan_id": plan_id,
        "target": target.id,
        "target_name": target.name,
        "status": "FAILED" if run_failed else "COMPLETE",
        "cases_total": len(config["cases"]),
        "cases_executed": len(results),
        "findings": findings,
        "no_findings": len(results) - findings - errors,
        "errors": errors,
        "duration_ms": round((perf_counter() - started) * 1000),
        "results": results,
    }
    lab_session.automation.reports.append(report)
    history_limit = min(
        max(1, int(config.get("report_history_limit", 5))), ABSOLUTE_REPORT_HISTORY
    )
    if len(lab_session.automation.reports) > history_limit:
        del lab_session.automation.reports[:-history_limit]
    return report
