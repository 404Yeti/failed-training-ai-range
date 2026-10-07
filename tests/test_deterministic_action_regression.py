"""Known hostile input tests the real defense, independently of inference."""
import asyncio
import copy
from dataclasses import replace
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

import app.action_defense as actions
from app.challenges import ChallengeRegistry
from app.defense import RegressionProposal, run_defense_suite
from tests.test_action_defense import target
from tests.test_rag_defense import run_api, start


class NoInference:
    def __init__(self):
        self.calls = 0

    async def complete(self, *args):
        self.calls += 1
        raise AssertionError('Defense regression must not call inference')

    complete_actions = complete


@pytest.mark.parametrize('enabled,score', [
    ([], 2), (['tool_allowlist'], 2), (['validate_arguments'], 3),
    (['tool_allowlist', 'validate_arguments'], 3),
    (['execution_authorization'], 6), (['impact_approval'], 6),
    (['least_privilege_tools'], 6), ([c.id for c in actions.CONTROLS], 6),
])
def test_all_cases_normalize_dispatch_and_grade_real_actions_without_inference(enabled, score):
    session = target(enabled)
    before = copy.deepcopy(session)
    provider = NoInference()
    events = []
    real = actions.dispatch_proposal

    def dispatch(child, proposal, source, turn):
        assert source == 'SERVER_FIXTURE' and turn == 1
        assert not child.history and not child.tool_state.audit
        assert not child.defense.action.refund_authorized
        assert not child.defense.action.refund_approved
        response, event = real(child, proposal, source, turn)
        events.append((child, event))
        return response, event

    with patch('app.action_defense.normalize_action_output', wraps=actions.normalize_action_output) as normalize, \
            patch('app.action_defense.dispatch_proposal', side_effect=dispatch), \
            patch('app.action_defense.execute_tool', wraps=actions.execute_tool) as executor:
        report = asyncio.run(run_defense_suite(session, provider))
    assert provider.calls == 0 and normalize.call_count == 6
    assert report['passed'] == score and report['errors'] == 0
    assert len(events) == 6 and len({id(child) for child, _ in events}) == 6
    assert session == before
    assert events[0][1]['tool'] == 'lookup_customer' and events[0][1]['executed']
    assert events[1][1]['tool'] == 'read_ticket' and events[1][1]['executed']
    assert executor.call_count == sum(event['executed'] for _, event in events)
    for child, event in events:
        assert event['schema_validation'] == 'PASS'
        if not event['executed']:
            assert not child.tool_state.refunds and not child.tool_state.drafts
    supervisor_child, supervisor = events[3]
    assert supervisor['authority_claim'] == 'UNTRUSTED_SUPERVISOR'
    assert 'supervisor' in supervisor_child.history[0]['content'].lower()
    assert not supervisor_child.defense.action.refund_authorized
    assert not supervisor_child.defense.action.refund_approved
    if 'execution_authorization' in enabled:
        assert events[4][1]['authorization'] == 'DENY'
        assert not events[4][1]['executed']
    contract = events[5][1]
    assert contract['amount'] == 1500
    if 'validate_arguments' in enabled:
        assert contract['argument_validation'] == 'DENY'
        assert contract['authorization'] == 'NOT_CHECKED'
    elif 'execution_authorization' in enabled:
        assert contract['argument_validation'] == 'NOT_CHECKED'
        assert contract['authorization'] == 'DENY'
    if 'impact_approval' in enabled and 'execution_authorization' not in enabled:
        assert events[4][1]['approval'] == 'APPROVAL_REQUIRED'
    if enabled == ['least_privilege_tools']:
        assert events[4][1]['profile_check'] == 'DENY'


@pytest.mark.parametrize('text', [
    'not JSON', '{"tool":"issue_refund","arguments":',
    '{"tool":"unknown","arguments":{}}',
    '{"tool":"lookup_customer","arguments":{"customer_id":"CUST-9999"}}',
    '{"tool":"read_ticket","arguments":{"ticket_id":"TKT-9999"}}',
    '{"tool":"issue_refund","arguments":{"customer_id":"CUST-1842","amount":10001}}',
    '{"tool":"issue_refund","arguments":{"customer_id":"CUST-1842","amount":NaN}}',
    '{"tool":"issue_refund","arguments":{"customer_id":"CUST-1842","amount":true}}',
    '{"tool":"issue_refund","arguments":{"customer_id":"CUST-1842","amount":0}}',
    '{"tool":"lookup_customer","arguments":{"customer_id":{"nested":"CUST-1842"}}}',
    '{"tool":"lookup_customer","arguments":{"customer_id":"CUST-1842","url":"external"}}',
    '{"tool":"issue_refund","arguments":{"customer_id":"CUST-1842"}}',
    'x' * 4097,
])
def test_invalid_server_fixture_fails_challenge_loading(text):
    invalid = replace(actions.CASES[0], proposal_fixture=RegressionProposal(text))
    with patch('app.action_defense.CASES', (invalid,)):
        with pytest.raises(ValueError, match='Invalid server-owned action regression fixture'):
            ChallengeRegistry(Path('challenges'))


@pytest.mark.parametrize('fixture', [None, RegressionProposal('{}', 'grant_permission')])
def test_missing_fixture_or_trusted_state_metadata_fails_loading(fixture):
    with patch('app.action_defense.CASES', (replace(actions.CASES[0], proposal_fixture=fixture),)):
        with pytest.raises(ValueError):
            ChallengeRegistry(Path('challenges'))


def test_fixture_processing_error_is_error_not_success():
    async def broken(*args):
        raise ValueError('fixture processing failed')
    lab = replace(actions.ACTION_LAB, process_fixture=broken)
    with patch('app.defense.get_defense_lab', return_value=lab):
        report = asyncio.run(run_defense_suite(target(['execution_authorization']), NoInference()))
    assert report['errors'] == 6 and report['passed'] == 0


def test_fixture_diagnostics_exclude_input_content_and_arguments(caplog):
    with caplog.at_level(logging.INFO, logger='airange.actions'):
        report = asyncio.run(run_defense_suite(target(['execution_authorization']), NoInference()))
    assert report['passed'] == 6
    records = [r.message for r in caplog.records if r.message.startswith('action_regression ')]
    assert len(records) == 6
    assert 'case_id=contract-bound' in caplog.text and 'proposal_source=SERVER_FIXTURE' in caplog.text
    assert 'authorized=DENY' in caplog.text and 'executed=False' in caplog.text
    for case in actions.CASES:
        assert case.prompts[0] not in caplog.text and case.proposal_fixture.text not in caplog.text
    for forbidden in ('CUST-1842', 'TKT-7721', '1500', '250', 'customer_id', 'arguments', 'Authorization:'):
        assert forbidden not in caplog.text


@pytest.mark.parametrize('field', ['proposal', 'proposal_fixture', 'authority_claim', 'cases'])
def test_client_cannot_supply_regression_input(field):
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        for endpoint in ('chat', 'apply', 'retest'):
            body = {'session_id': sid, field: {'tool': 'issue_refund'}}
            if endpoint == 'chat':
                body['message'] = 'hello'
            if endpoint == 'apply':
                body['enabled'] = []
            assert (await client.post('/api/defense/' + endpoint, json=body)).status_code == 422
    run_api(scenario)


def test_api_retest_zero_calls_with_unavailable_provider():
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        await client.post('/api/defense/apply', json={'session_id': sid, 'enabled': ['execution_authorization']})
        provider = NoInference()
        app.state.llm = provider
        response = await client.post('/api/defense/retest', json={'session_id': sid})
        assert response.status_code == 200 and response.json()['report']['passed'] == 6
        assert provider.calls == 0
    run_api(scenario)


@pytest.mark.parametrize('lab', ['AG-001', 'BT-005'])
@pytest.mark.parametrize('format', ['TEXT', 'NATIVE_TOOL', 'NONE'])
def test_manual_labs_still_infer_and_accept_existing_formats(lab, format):
    from tests.test_action_protocol import provider, action
    from tests.test_native_action_output import native, envelope
    from tests.test_llm import FakeResponse, run_inline

    message = native('lookup_customer', {'customer_id': 'CUST-1842'}) if format == 'NATIVE_TOOL' else {
        'content': action('lookup_customer', customer_id='CUST-1842') if format == 'TEXT' else 'Hello.'}
    response_body = envelope(message, 'tool_calls' if format == 'NATIVE_TOOL' else 'stop')

    async def scenario(client, app):
        sid = await start(client, lab)
        app.state.llm.provider = provider()
        path = '/api/defense/chat' if lab == 'BT-005' else '/api/challenge/AG-001/chat'
        response = await client.post(path, json={'session_id': sid, 'message': 'Hello.'})
        assert response.status_code == 200
        audit = app.state.sessions.get(sid).tool_state.audit
        if format == 'NONE':
            assert not audit
        else:
            assert audit[-1]['tool'] == 'lookup_customer' and audit[-1]['executed']

    with patch('app.llm.request.urlopen', return_value=FakeResponse(response_body)) as inference, \
            patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)
    assert inference.call_count == 1
