"""Normalize hostile provider output, without authorizing or executing actions."""
from dataclasses import dataclass
import json

from app.action_diagnostics import proposal_source, stage
from app.tools import ARGUMENTS, MAX_ARGUMENT_BYTES, ToolRequest, ToolRequestError, parse_tool_request, strict_json_object


@dataclass(frozen=True)
class ActionOutput:
    text: str
    proposal: ToolRequest | None
    source: str


class ActionOutputError(ValueError):
    def __init__(self, source='INVALID'):
        super().__init__('Invalid provider action output')
        self.source = source


def normalize_action_output(message: dict, finish_reason=None) -> ActionOutput:
    """Exactly one proposal; never repair malformed native output into prose."""
    source = 'INVALID'
    stage('proposal_normalization')
    try:
        if not isinstance(message, dict) or message.get('function_call') or message.get('executed_tools'):
            raise ActionOutputError()
        content = message.get('content')
        calls = message.get('tool_calls')
        if calls is not None and not isinstance(calls, list):
            raise ActionOutputError()
        if finish_reason not in (None, 'stop', 'tool_calls'):
            raise ActionOutputError()
        if calls:
            if len(calls) != 1:
                raise ActionOutputError('AMBIGUOUS')
            if finish_reason != 'tool_calls':
                raise ActionOutputError()
            # Optional metadata fields follow Groq's published message spec;
            # none of them grants authority or is retained/logged.
            fields = {'role', 'content', 'tool_calls', 'reasoning', 'annotations', 'refusal', 'function_call', 'executed_tools'}
            if set(message) - fields or message.get('role', 'assistant') != 'assistant':
                raise ActionOutputError()
            if content is not None and not isinstance(content, str):
                raise ActionOutputError()
            # A second structured/textual proposal is ambiguous, even if equal.
            # Ordinary prose is non-authoritative and deliberately discarded.
            if content and any(marker in content for marker in ('{', '[', '```')):
                raise ActionOutputError('AMBIGUOUS')
            call = calls[0]
            if not isinstance(call, dict) or set(call) != {'id', 'type', 'function'}:
                raise ActionOutputError()
            if call['type'] != 'function' or not isinstance(call['id'], str) or not 1 <= len(call['id']) <= 128:
                raise ActionOutputError()
            function = call['function']
            if not isinstance(function, dict) or set(function) != {'name', 'arguments'}:
                raise ActionOutputError()
            name, raw_arguments = function['name'], function['arguments']
            if not isinstance(name, str) or name not in ARGUMENTS:
                raise ActionOutputError()
            if not isinstance(raw_arguments, str) or len(raw_arguments.encode('utf-8')) > MAX_ARGUMENT_BYTES:
                raise ActionOutputError()
            arguments = strict_json_object(raw_arguments)
            text = json.dumps({'tool': name, 'arguments': arguments}, allow_nan=False)
            proposal = parse_tool_request(text, list(ARGUMENTS))
            source = 'NATIVE_TOOL'
            return ActionOutput(text, proposal, source)
        if finish_reason == 'tool_calls' or not isinstance(content, str) or not content.strip():
            raise ActionOutputError()
        source = 'NONE'
        if content.lstrip().startswith(('[', '```')) and not content.lstrip().startswith('```json'):
            source = 'INVALID'
            return ActionOutput(content, None, source)
        try:
            proposal = parse_tool_request(content, list(ARGUMENTS))
            if proposal is not None:
                source = 'TEXT'
                content = json.dumps({'tool': proposal.tool, 'arguments': proposal.arguments}, allow_nan=False)
        except ToolRequestError:
            # Preserve textual invalid proposals for the existing denial/audit
            # path. They must not be replaced by the support intent adapter.
            source, proposal = 'INVALID', None
        return ActionOutput(content, proposal, source)
    except ActionOutputError as exc:
        source = exc.source
        raise
    except (ToolRequestError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ActionOutputError() from exc
    finally:
        proposal_source(source)


async def complete_action_output(llm, messages, flag, available) -> ActionOutput:
    method = getattr(llm, 'complete_actions', None)
    if method is not None:
        return await method(messages, flag, available)
    return normalize_action_output({'content': await llm.complete(messages, flag)})
