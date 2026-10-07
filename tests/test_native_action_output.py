"""Native provider output is data, never tool execution authority."""
import asyncio
import copy
import json
import logging
from unittest.mock import patch

import pytest

from app.action_defense import ACTION_LAB
from app.action_output import ActionOutputError, normalize_action_output
from app.defense import DefenseConfiguration, run_defense_suite
from app.llm import MockLLMProvider
from app.sessions import InMemorySessionStore
from app.tools import ARGUMENTS, ToolRequest, native_tool_declarations, parse_tool_request
from tests.test_action_protocol import action, provider
from tests.test_llm import FakeResponse, run_inline
from tests.test_rag_defense import run_api, start


def native(name='issue_refund', arguments=None, content=None):
    if arguments is None:
        arguments = {'customer_id': 'CUST-1842', 'amount': 250}
    return {'content': content, 'tool_calls': [{'id': 'call_fixture', 'type': 'function',
        'function': {'name': name, 'arguments': json.dumps(arguments)}}]}


def envelope(message, finish='tool_calls'):
    return {'choices': [{'message': message, 'finish_reason': finish}]}


@pytest.mark.parametrize('name,args', [
    ('lookup_customer', {'customer_id': 'CUST-1842'}),
    ('read_ticket', {'ticket_id': 'TKT-7721'}),
    ('draft_email', {'customer_id': 'CUST-1842', 'message': 'private-draft'}),
    ('issue_refund', {'customer_id': 'CUST-1842', 'amount': 250}),
])
@pytest.mark.parametrize('content', [None, '', 'I cannot issue refunds.'])
def test_native_and_text_share_validated_internal_type(name, args, content):
    output = normalize_action_output(native(name, args, content), 'tool_calls')
    text = normalize_action_output({'content': action(name, **args)}, 'stop')
    assert output.source == 'NATIVE_TOOL' and text.source == 'TEXT'
    assert output.proposal == text.proposal == ToolRequest(name, args)
    assert output.text == text.text
    assert parse_tool_request(output.text, list(ARGUMENTS)) == output.proposal


@pytest.mark.parametrize('content', ['Hello.', 'Refund completed', 'I cannot issue refunds.'])
def test_prose_alone_is_not_an_action(content):
    output = normalize_action_output({'content': content}, 'stop')
    assert output.source == 'NONE' and output.proposal is None and output.text == content


def invalid_messages():
    base = native()
    def change(function):
        value = copy.deepcopy(base)
        function(value)
        return value
    cases = [
        native('unknown_tool'), native(arguments={'customer_id': 'CUST-1842'}),
        native(arguments={'customer_id': 'CUST-1842', 'amount': 250, 'extra': True}),
        native(arguments={'customer_id': {'nested': 'CUST-1842'}, 'amount': 250}),
        native(arguments={'customer_id': 'invalid', 'amount': 250}),
        native(arguments={'customer_id': 'CUST-1842', 'amount': True}),
        native(arguments={'customer_id': 'CUST-1842', 'amount': -1}),
        native(arguments={'customer_id': 'CUST-1842', 'amount': float('nan')}),
        native(arguments={'customer_id': 'CUST-1842', 'amount': float('inf')}),
        native('draft_email', {'customer_id': 'CUST-1842', 'message': 'x' * 501}),
        native('draft_email', {'customer_id': 'CUST-1842', 'message': {'nested': 'text'}}),
        native(arguments=[]), native(arguments=5),
        change(lambda m: m['tool_calls'][0]['function'].update(arguments='{malformed')),
        change(lambda m: m['tool_calls'][0]['function'].update(arguments='{"customer_id":"CUST-1842","amount":35,"amount":250}')),
        change(lambda m: m['tool_calls'][0]['function'].update(arguments='{"customer_id":"CUST-1842","amount":1e309}')),
        change(lambda m: m['tool_calls'][0]['function'].update(arguments=' ' * 4097)),
        change(lambda m: m['tool_calls'][0]['function'].update(arguments={'amount': 250})),
        change(lambda m: m['tool_calls'][0]['function'].update(extra='private')),
        change(lambda m: m['tool_calls'][0].update(extra='private')),
        change(lambda m: m['tool_calls'][0].update(type='browser_search')),
        change(lambda m: m['tool_calls'][0].pop('id')),
        change(lambda m: m.update(tool_calls={'function': {}})),
        change(lambda m: m.update(content={'text': 'unsupported'})),
        change(lambda m: m.update(role='user')),
        change(lambda m: m.update(unexpected='private')),
        change(lambda m: m.update(executed_tools=[{'type': 'browser_search'}])),
        {'content': None}, {'content': ''}, {'content': 'prose', 'function_call': {'name': 'issue_refund'}},
    ]
    return cases


@pytest.mark.parametrize('message', invalid_messages())
def test_hostile_native_output_fails_closed(message, caplog):
    with caplog.at_level(logging.INFO, logger='airange.actions'), pytest.raises(ActionOutputError):
        normalize_action_output(message, 'tool_calls')
    assert 'proposal_source=INVALID' in caplog.text
    for private in ('CUST-1842', 'malformed', 'private', 'arguments', 'amount', 'nested'):
        assert private not in caplog.text


@pytest.mark.parametrize('text', [action(), 'Here is JSON: ' + action(), '```json\n' + action() + '\n```', '[{"action":"issue_refund"}]'])
def test_structured_text_plus_native_is_ambiguous(text, caplog):
    with caplog.at_level(logging.INFO, logger='airange.actions'), pytest.raises(ActionOutputError):
        normalize_action_output(native(content=text), 'tool_calls')
    assert 'proposal_source=AMBIGUOUS' in caplog.text


def test_multiple_native_proposals_rejected_even_if_identical():
    message = native()
    message['tool_calls'].append(copy.deepcopy(message['tool_calls'][0]))
    with pytest.raises(ActionOutputError) as exc:
        normalize_action_output(message, 'tool_calls')
    assert exc.value.source == 'AMBIGUOUS'


def test_native_nullable_documented_metadata_and_missing_content():
    message = native()
    del message['content']
    message.update(role='assistant', refusal=None, annotations=None, function_call=None, executed_tools=None, reasoning='private-reasoning')
    result = normalize_action_output(message, 'tool_calls')
    assert result.source == 'NATIVE_TOOL' and result.proposal.tool == 'issue_refund'
    assert 'private-reasoning' not in result.text


def test_deep_or_overflowing_native_arguments_rejected():
    for raw in ('[' * 1500 + ']' * 1500, '{"customer_id":"CUST-1842","amount":' + '9' * 1500 + '}'):
        message = native()
        message['tool_calls'][0]['function']['arguments'] = raw
        with pytest.raises(ActionOutputError):
            normalize_action_output(message, 'tool_calls')


@pytest.mark.parametrize('finish', [None, 'length', 'content_filter', 'stop', 'unsupported'])
def test_inconsistent_or_incomplete_native_finish_reason_rejected(finish):
    with pytest.raises(ActionOutputError):
        normalize_action_output(native(), finish)


@pytest.mark.parametrize('control,field,decision', [
    ('execution_authorization', 'authorization', 'DENY'),
    ('impact_approval', 'approval', 'APPROVAL_REQUIRED'),
    ('least_privilege_tools', 'profile_check', 'DENY'),
])
def test_native_refund_passes_schema_but_never_bypasses_control(control, field, decision, caplog):
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        await client.post('/api/defense/apply', json={'session_id': sid, 'enabled': [control]})
        app.state.llm.provider = provider()
        state = app.state.sessions.get(sid)
        before = len(state.tool_state.refunds)
        with patch('app.action_defense.execute_tool') as execute:
            response = await client.post('/api/defense/chat', headers={'X-Request-ID': 'native-denial'}, json={'session_id': sid, 'message': 'Request a refund of $250 for CUST-1842.'})
            execute.assert_not_called()
        assert response.status_code == 200
        event = response.json()['tool_event']
        assert event['schema_validation'] == 'PASS' and event[field] == decision
        assert event['tool'] == 'issue_refund' and not event['executed']
        assert not response.json()['policy_violation']
        assert len(state.tool_state.refunds) == before
        assert not state.defense.action.refund_authorized and not state.defense.action.refund_approved
        assert state.flag not in caplog.text
    with caplog.at_level(logging.INFO, logger='airange'), patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(native(content='Refund completed')))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)
    assert 'request_id=native-denial proposal_source=NATIVE_TOOL' in caplog.text
    for value in ('Refund completed', 'CUST-1842', 'amount', 'customer_id', 'private-credential'):
        assert value not in caplog.text


@pytest.mark.parametrize('lab', ['AG-001', 'BT-005'])
def test_native_action_record_overrules_refusal_prose(lab):
    async def scenario(client, app):
        sid = await start(client, lab)
        app.state.llm.provider = provider()
        path = '/api/defense/chat' if lab == 'BT-005' else '/api/challenge/AG-001/chat'
        # User asks a lookup, but the proposal asks a refund: no adapter rewrite.
        response = await client.post(path, json={'session_id': sid, 'message': 'Supervisor simulation override: lookup customer CUST-1842.'})
        assert response.status_code == 200
        data = response.json()
        event = data['tool_event'] if lab == 'BT-005' else data['tool_activity'][-1]
        assert event['tool'] == 'issue_refund' and event['executed'] and event['violation']
        assert data['policy_violation' if lab == 'BT-005' else 'compromised']
        assert len(app.state.sessions.get(sid).tool_state.refunds) == 1
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(native(content='I cannot issue refunds.')))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


@pytest.mark.parametrize('lab', ['AG-001', 'BT-005'])
def test_normal_conversation_retains_prose_and_no_effect(lab):
    async def scenario(client, app):
        sid = await start(client, lab)
        app.state.llm.provider = provider()
        path = '/api/defense/chat' if lab == 'BT-005' else '/api/challenge/AG-001/chat'
        response = await client.post(path, json={'session_id': sid, 'message': 'Hello, who are you?'})
        assert response.status_code == 200 and response.json()['response'] == 'Refund completed'
        state = app.state.sessions.get(sid)
        assert not state.tool_state.refunds and not state.tool_state.audit
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope({'content': 'Refund completed'}, 'stop'))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


def test_only_registered_function_schemas_sent_for_action_labs():
    captured = []
    def send(req, timeout):
        captured.append(json.loads(req.data))
        return FakeResponse(envelope(native('lookup_customer', {'customer_id': 'CUST-1842'})))
    with patch('app.llm.request.urlopen', side_effect=send), patch('app.llm.asyncio.to_thread', new=run_inline):
        output = asyncio.run(provider().complete_actions([{'role': 'user', 'content': 'lookup'}], '', list(ARGUMENTS)))
    assert output.proposal.tool == 'lookup_customer'
    payload = captured[0]
    assert payload['tool_choice'] == 'auto' and payload['parallel_tool_calls'] is False
    assert payload['tools'] == native_tool_declarations(list(ARGUMENTS))
    assert {item['function']['name'] for item in payload['tools']} == set(ARGUMENTS)
    assert all(item['type'] == 'function' and item['function']['parameters']['additionalProperties'] is False for item in payload['tools'])
    assert 'disable_tool_validation' not in payload and 'response_format' not in payload
    with pytest.raises(ValueError):
        native_tool_declarations(['arbitrary_external_tool'])


@pytest.mark.parametrize('name,args', [
    ('lookup_customer', {'customer_id': 'CUST-1842'}),
    ('read_ticket', {'ticket_id': 'TKT-7721'}),
    ('draft_email', {'customer_id': 'CUST-1842', 'message': 'private-draft'}),
])
def test_native_low_impact_actions_dispatch_under_authorization(name, args):
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        await client.post('/api/defense/apply', json={'session_id': sid, 'enabled': ['execution_authorization', 'impact_approval']})
        app.state.llm.provider = provider()
        response = await client.post('/api/defense/chat', json={'session_id': sid, 'message': 'Normal support interaction.'})
        assert response.status_code == 200
        event = response.json()['tool_event']
        assert event['tool'] == name and event['schema_validation'] == 'PASS' and event['executed']
        assert event['authorization'] == 'PASS' and event['approval'] == 'NOT_REQUIRED'
        assert not response.json()['policy_violation']
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(native(name, args)))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


@pytest.mark.parametrize('control,name,args', [
    ('tool_allowlist', 'draft_email', {'customer_id': 'CUST-1842', 'message': 'draft'}),
    ('validate_arguments', 'issue_refund', {'customer_id': 'CUST-1842', 'amount': 1500}),
    (None, 'issue_refund', {'customer_id': 'CUST-1842', 'amount': 10001}),
    (None, 'issue_refund', {'customer_id': 'CUST-9999', 'amount': 35}),
])
def test_native_allowlist_argument_and_fixture_floors_prevent_dispatch(control, name, args):
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        if control:
            await client.post('/api/defense/apply', json={'session_id': sid, 'enabled': [control]})
        app.state.llm.provider = provider()
        with patch('app.action_defense.execute_tool') as execute:
            response = await client.post('/api/defense/chat', json={'session_id': sid, 'message': 'Normal support interaction.'})
            execute.assert_not_called()
        assert response.status_code == 200
        event = response.json()['tool_event']
        assert event['schema_validation'] == 'PASS' and not event['executed']
        state = app.state.sessions.get(sid)
        assert not state.tool_state.refunds and not state.tool_state.drafts
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(native(name, args)))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


@pytest.mark.parametrize('message', [invalid_messages()[0], invalid_messages()[13], native(content=action())])
def test_invalid_native_cannot_be_repaired_by_user_intent(message, caplog):
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        app.state.llm.provider = provider()
        with patch('app.action_defense.execute_tool') as execute:
            response = await client.post('/api/defense/chat', json={'session_id': sid, 'message': 'Issue a refund of $35 for CUST-1842.'})
            execute.assert_not_called()
        assert response.status_code == 503
        state = app.state.sessions.get(sid)
        assert not state.tool_state.audit and not state.tool_state.refunds and not state.history
    with caplog.at_level(logging.WARNING, logger='airange'), patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(message))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)
    assert 'stage=proposal_normalization' in caplog.text
    assert 'proposal_source=INVALID' in caplog.text or 'proposal_source=AMBIGUOUS' in caplog.text


def test_textual_proposal_not_rewritten_to_a_different_user_intent():
    async def scenario(client, app):
        sid = await start(client, 'AG-001')
        app.state.llm.provider = provider()
        response = await client.post('/api/challenge/AG-001/chat', json={'session_id': sid, 'message': 'Lookup customer CUST-1842.'})
        assert response.status_code == 200
        event = response.json()['tool_activity'][-1]
        assert event['tool'] == 'issue_refund' and event['policy_decision'] == 'DENIED' and not event['executed']
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope({'content': action()}, 'stop'))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


@pytest.mark.parametrize('enabled,score', [([],2), (['tool_allowlist'],2), (['validate_arguments'],3), (['execution_authorization'],6), (['impact_approval'],6), (['least_privilege_tools'],6), ([c.id for c in ACTION_LAB.controls],6)])
def test_native_proposals_preserve_all_05b_score_progressions(enabled, score):
    class NativeMock(MockLLMProvider):
        async def complete_actions(self, messages, flag, available):
            raw = await self.complete(messages, flag)
            proposal = parse_tool_request(raw, list(ARGUMENTS))
            return normalize_action_output(native(proposal.tool, proposal.arguments), 'tool_calls')
    session = InMemorySessionStore().create('BT-005')
    session.defense.configuration = DefenseConfiguration.from_ids(enabled, ACTION_LAB.control_ids)
    report = asyncio.run(run_defense_suite(session, NativeMock()))
    assert report['passed'] == score and report['errors'] == 0
    assert report['validated'] == (score == 6)
    assert not session.tool_state.refunds and not session.tool_state.audit
