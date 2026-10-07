"""Keep provider proposal structure separate from 05B execution contracts."""
import asyncio
import json
from unittest.mock import patch

import pytest

from app.action_defense import ACTION_LAB, MAX_SIMULATED_REFUND, VALIDATED_REFUND_LIMIT, capability_tools
from app.tools import ARGUMENTS, execute_tool, native_tool_declarations
from tests.test_action_protocol import provider
from tests.test_llm import FakeResponse, run_inline
from tests.test_native_action_output import envelope, native
from tests.test_rag_defense import run_api, start


@pytest.mark.parametrize('amount', [35, 250, 500, 1500, 10001])
def test_actual_provider_request_has_no_educational_refund_maximum(amount):
    captured = []
    def send(req, timeout):
        captured.append(json.loads(req.data))
        return FakeResponse(envelope(native(arguments={'customer_id': 'CUST-1842', 'amount': amount})))
    with patch('app.llm.request.urlopen', side_effect=send), patch('app.llm.asyncio.to_thread', new=run_inline):
        result = asyncio.run(provider().complete_actions([{'role': 'user', 'content': 'support'}], '', list(ARGUMENTS)))
    declaration = next(item['function'] for item in captured[0]['tools'] if item['function']['name'] == 'issue_refund')
    assert declaration['parameters']['properties']['amount'] == {'type': 'number', 'exclusiveMinimum': 0}
    assert declaration['parameters']['required'] == ['amount', 'customer_id']
    assert declaration['parameters']['additionalProperties'] is False
    assert result.proposal.tool == 'issue_refund' and result.proposal.arguments['amount'] == amount
    assert 'disable_tool_validation' not in captured[0]


@pytest.mark.parametrize('enabled', [[], ['validate_arguments'], ['execution_authorization'], ['impact_approval'], ['validate_arguments', 'execution_authorization']])
def test_application_amount_permission_and_approval_controls_do_not_change_provider_schema(enabled):
    names = capability_tools(frozenset(enabled))
    declarations = native_tool_declarations(names)
    assert declarations == native_tool_declarations(list(ARGUMENTS))
    refund = next(item['function'] for item in declarations if item['function']['name'] == 'issue_refund')
    assert set(refund['parameters']) == {'type', 'properties', 'required', 'additionalProperties'}
    assert 'enum' not in refund['parameters']['properties']['customer_id']


@pytest.mark.parametrize('amount,expected', [(35, 'PASS'), (250, 'PASS'), (500, 'PASS'), (1500, 'DENY')])
def test_native_refund_contract_boundary_runs_in_application(amount, expected):
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        await client.post('/api/defense/apply', json={'session_id': sid, 'enabled': ['validate_arguments', 'execution_authorization']})
        app.state.llm.provider = provider()
        before = len(app.state.sessions.get(sid).tool_state.refunds)
        with patch('app.action_defense.execute_tool') as execute:
            response = await client.post('/api/defense/chat', json={'session_id': sid, 'message': 'Normal support request.'})
            execute.assert_not_called()
        assert response.status_code == 200
        event = response.json()['tool_event']
        assert event['schema_validation'] == 'PASS'
        assert event['argument_validation'] == expected and not event['executed']
        if amount > VALIDATED_REFUND_LIMIT:
            assert event['reason'] == 'REFUND EXCEEDS $500 TOOL CONTRACT'
            assert event['authorization'] == 'NOT_CHECKED'
        else:
            assert event['authorization'] == 'DENY'
        assert len(app.state.sessions.get(sid).tool_state.refunds) == before
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(native(arguments={'customer_id': 'CUST-1842', 'amount': amount})))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


def test_absolute_ceiling_remains_application_owned_even_without_optional_controls():
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        app.state.llm.provider = provider()
        with patch('app.action_defense.execute_tool') as execute:
            response = await client.post('/api/defense/chat', json={'session_id': sid, 'message': 'Normal support request.'})
            execute.assert_not_called()
        assert response.status_code == 200
        event = response.json()['tool_event']
        assert event['schema_validation'] == 'PASS' and not event['executed']
        assert event['reason'] == 'OUTSIDE BOUNDED FIXTURE CONTRACT'
        assert not app.state.sessions.get(sid).tool_state.refunds
    message = native(arguments={'customer_id': 'CUST-1842', 'amount': MAX_SIMULATED_REFUND + 1})
    with patch('app.llm.request.urlopen', return_value=FakeResponse(envelope(message))), patch('app.llm.asyncio.to_thread', new=run_inline):
        run_api(scenario)


def test_retest_does_not_call_provider_or_hide_provider_errors():
    async def scenario(client, app):
        sid = await start(client, 'BT-005')
        await client.post('/api/defense/apply', json={'session_id': sid, 'enabled': ['validate_arguments', 'execution_authorization']})
        app.state.llm.provider = provider()
        with patch('app.action_defense.execute_tool', wraps=execute_tool) as execute:
            response = await client.post('/api/defense/retest', json={'session_id': sid})
        assert response.status_code == 200
        assert response.json()['report']['passed'] == 6
        assert response.json()['report']['errors'] == 0
        assert execute.call_count == 2
        assert not app.state.sessions.get(sid).tool_state.refunds
    with patch('app.llm.request.urlopen', side_effect=AssertionError('No inference allowed')) as send_spy:
        run_api(scenario)
    send_spy.assert_not_called()


@pytest.mark.parametrize('enabled', [['least_privilege_tools'], [item.id for item in ACTION_LAB.controls]])
def test_least_privilege_removes_refund_declaration_rather_than_lowering_amount_maximum(enabled):
    declared = native_tool_declarations(capability_tools(frozenset(enabled)))
    assert 'issue_refund' not in {item['function']['name'] for item in declared}
