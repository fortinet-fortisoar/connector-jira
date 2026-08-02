"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

"""Tests for the Jira connector — focused on the v3.0.0 multi-deployment / multi-auth changes."""

import json
from base64 import b64encode

import pytest


@pytest.fixture
def ops(load_connector):
    return load_connector('jira')


def _cloud_config(**overrides):
    base = {
        'server_url': 'https://acme.atlassian.net',
        'auth_type': 'Cloud (Email + API Token)',
        'username': 'alice@example.com',
        'token': 'cloud-tok',
        'verify_ssl': False,
    }
    base.update(overrides)
    return base


def _server_pat_config(**overrides):
    base = {
        'server_url': 'https://jira.acme.local',
        'auth_type': 'Server / Data Center (Personal Access Token)',
        'pat': 'pat-xyz',
        'verify_ssl': False,
    }
    base.update(overrides)
    return base


def _server_basic_config(**overrides):
    base = {
        'server_url': 'https://jira.acme.local',
        'auth_type': 'Server / Data Center (Username + Password)',
        'username': 'sysadmin',
        'password': 'pw', #pragma: allowlist secret
        'verify_ssl': False,
    }
    base.update(overrides)
    return base


def test_helpers_classify_deployment(ops):
    assert ops._is_cloud(_cloud_config()) is True
    assert ops._is_cloud(_server_pat_config()) is False
    assert ops._api_version(_cloud_config()) == '3'
    assert ops._api_version(_server_pat_config()) == '2'
    assert ops._api_version(_server_basic_config()) == '2'
    assert ops._issue_endpoint(_cloud_config()) == '/rest/api/3/issue/'
    assert ops._issue_endpoint(_server_pat_config()) == '/rest/api/2/issue/'
    assert ops._search_jql_endpoint(_cloud_config()) == '/rest/api/3/search/jql'
    assert ops._search_jql_endpoint(_server_pat_config()) == '/rest/api/2/search'


def test_description_body_cloud_returns_adf(ops):
    body = ops._description_body('hello', _cloud_config())
    assert body['type'] == 'doc'
    assert body['content'][0]['content'][0]['text'] == 'hello'


def test_description_body_server_returns_plain_string(ops):
    assert ops._description_body('hello', _server_pat_config()) == 'hello'
    assert ops._description_body('hi', _server_basic_config()) == 'hi'


def test_description_body_empty_passthrough(ops):
    assert ops._description_body('', _cloud_config()) == ''
    assert ops._description_body(None, _server_pat_config()) is None


def test_make_api_call_cloud_uses_basic_auth(ops, requests_mock):
    requests_mock.get('https://acme.atlassian.net/rest/api/3/myself', json={'self': 'x'}, status_code=200)
    resp = ops.make_api_call(_cloud_config(), 'GET', endpoint='/rest/api/3/myself')
    assert resp.ok
    sent = requests_mock.last_request.headers
    expected = 'Basic ' + b64encode(b'alice@example.com:cloud-tok').decode()
    assert sent['Authorization'] == expected


def test_make_api_call_server_pat_uses_bearer(ops, requests_mock):
    requests_mock.get('https://jira.acme.local/rest/api/2/myself', json={}, status_code=200)
    ops.make_api_call(_server_pat_config(), 'GET', endpoint='/rest/api/2/myself')
    sent = requests_mock.last_request.headers
    assert sent['Authorization'] == 'Bearer pat-xyz'


def test_make_api_call_server_basic_uses_basic(ops, requests_mock):
    requests_mock.get('https://jira.acme.local/rest/api/2/myself', json={}, status_code=200)
    ops.make_api_call(_server_basic_config(), 'GET', endpoint='/rest/api/2/myself')
    sent = requests_mock.last_request.headers
    expected = 'Basic ' + b64encode(b'sysadmin:pw').decode()
    assert sent['Authorization'] == expected


def test_make_api_call_unauthorized_raises_clean_error(ops, requests_mock):
    requests_mock.get('https://acme.atlassian.net/rest/api/3/myself', status_code=401, text='nope')
    with pytest.raises(Exception) as exc:
        ops.make_api_call(_cloud_config(), 'GET', endpoint='/rest/api/3/myself')
    assert 'Unauthorized' in str(exc.value)


def test_create_ticket_cloud_sends_adf_description(ops, requests_mock):
    requests_mock.post('https://acme.atlassian.net/rest/api/3/issue/',
                       json={'key': 'PROJ-1', 'id': '10001', 'self': 'x'}, status_code=201)
    requests_mock.get('https://acme.atlassian.net/rest/api/3/issue/PROJ-1',
                      json={'fields': {'status': {'name': 'To Do'}}}, status_code=200)
    result = ops.create_ticket(_cloud_config(), {
        'project_key': 'PROJ', 'ticket_summary': 's', 'ticket_description': 'd',
        'issue_type': 'Task', 'priority': 'Medium',
    })
    assert result['key'] == 'PROJ-1'
    body = json.loads(requests_mock.request_history[0].body)
    assert body['fields']['description']['type'] == 'doc'


def test_create_ticket_server_sends_plain_description(ops, requests_mock):
    requests_mock.post('https://jira.acme.local/rest/api/2/issue/',
                       json={'key': 'PROJ-2', 'id': '20002', 'self': 'x'}, status_code=201)
    requests_mock.get('https://jira.acme.local/rest/api/2/issue/PROJ-2',
                      json={'fields': {'status': {'name': 'Open'}}}, status_code=200)
    result = ops.create_ticket(_server_pat_config(), {
        'project_key': 'PROJ', 'ticket_summary': 's', 'ticket_description': 'plain text',
        'issue_type': 'Bug', 'priority': 'Low',
    })
    assert result['key'] == 'PROJ-2'
    body = json.loads(requests_mock.request_history[0].body)
    assert body['fields']['description'] == 'plain text'


def test_users_search_uses_correct_endpoint_per_deployment(ops, requests_mock, monkeypatch):
    # Cloud variant: /rest/api/3/users/search
    requests_mock.get('https://acme.atlassian.net/rest/api/3/users/search', json=[], status_code=200)
    ops.search_users(_cloud_config(), {})
    assert requests_mock.last_request.path == '/rest/api/3/users/search'

    # Server variant: /rest/api/2/user/search
    requests_mock.get('https://jira.acme.local/rest/api/2/user/search', json=[], status_code=200)
    ops.search_users(_server_pat_config(), {'username': 'q'})
    assert requests_mock.last_request.path == '/rest/api/2/user/search'


def test_jql_parse_blocked_on_server(ops):
    with pytest.raises(Exception) as exc:
        ops.validate_jql_query(_server_pat_config(), {'queries': ['x']})
    assert 'Cloud' in str(exc.value)
