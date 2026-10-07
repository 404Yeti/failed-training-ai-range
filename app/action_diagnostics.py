"""Content-free diagnostics for application-owned action processing."""
from contextvars import ContextVar
from functools import wraps
import logging
from time import perf_counter

request_id = ContextVar('action_request_id', default='unavailable')
_stage = ContextVar('action_stage', default=None)
logger = logging.getLogger('airange.actions')


def stage(name: str) -> None:
    trace = _stage.get()
    if trace is not None:
        trace['stage'] = name


def proposal_source(source: str) -> None:
    if source in {'TEXT', 'NATIVE_TOOL', 'NONE', 'INVALID', 'AMBIGUOUS'}:
        trace = _stage.get()
        if trace is not None:
            trace['proposal_source'] = source
        logger.info('action_output request_id=%s proposal_source=%s', request_id.get(), source)


def log_failure(exc: Exception, lab_id: str, name: str, started: float) -> None:
    from app.llm import LLMError

    provider = isinstance(exc, LLMError)
    category = getattr(exc, 'upstream_error_code', None) if provider else None
    if category not in {'tool_use_failed', 'output_parse_failed'}:
        category = 'other' if provider else 'not_applicable'
    logger.warning(
        'action_failure request_id=%s lab_id=%s stage=%s exception_class=%s '
        'provider_status=%s provider_category=%s duration_ms=%d proposal_source=%s',
        request_id.get(), lab_id, name, type(exc).__name__,
        exc.upstream_status if provider else None, category,
        round((perf_counter() - started) * 1000),
        (_stage.get() or {}).get('proposal_source', 'NONE'),
    )


def diagnose(lab_id: str):
    def decorate(function):
        @wraps(function)
        async def wrapped(*args, **kwargs):
            trace = {'stage': 'application_processing'}
            token = _stage.set(trace)
            started = perf_counter()
            try:
                return await function(*args, **kwargs)
            except Exception as exc:
                log_failure(exc, lab_id, trace['stage'], started)
                raise
            finally:
                _stage.reset(token)
        return wrapped
    return decorate
