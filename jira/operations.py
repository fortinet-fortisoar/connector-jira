"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import requests, json, os, re
from base64 import b64encode
from os.path import join
from integrations.crudhub import make_request
from requests_toolbelt.multipart.encoder import MultipartEncoder
from connectors.cyops_utilities.builtins import download_file_from_cyops
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings

logger = get_logger('jira')

CLOUD_AUTH = 'Cloud (Email + API Token)'
SERVER_PAT_AUTH = 'Server / Data Center (Personal Access Token)'
SERVER_BASIC_AUTH = 'Server / Data Center (Username + Password)'


def _auth_type(config):
    return (config.get('auth_type') or CLOUD_AUTH).strip()


def _is_cloud(config):
    return _auth_type(config) == CLOUD_AUTH


def _api_version(config):
    # Cloud -> v3, Server / Data Center -> v2
    return '3' if _is_cloud(config) else '2'


def _issue_endpoint(config):
    return '/rest/api/{0}/issue/'.format(_api_version(config))


def _search_jql_endpoint(config):
    # v3 has /search/jql, v2 uses /search
    return '/rest/api/3/search/jql' if _is_cloud(config) else '/rest/api/2/search'


def _description_body(text, config):
    """Cloud requires Atlassian Document Format; Server / DC takes a plain string."""
    if not text:
        return text
    if _is_cloud(config):
        return {
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": text}],
            }],
        }
    return text


def _comment_add_body(text, config):
    """Body shape for issue.update -> update.comment[].add.body."""
    if not text:
        return text
    return _description_body(text, config) if _is_cloud(config) else text


# Kept for backward compatibility — defaults to Cloud (v3) if a caller imports it directly.
ENDPOINT = '/rest/api/3/issue/'
SEARCH_JQL_ENDPOINT = '/rest/api/3/search/jql'

reserved_words = ["abort", "access", "add", "after", "alias", "all", "alter", "and", "any", "as", "asc", "audit", "avg",
                  "before", "begin", "between", "boolean", "break", "by", "byte", "catch", "cf", "char", "character",
                  "check", "checkpoint", "collate", "collation", "column", "commit", "connect", "continue", "count",
                  "create", "current", "date", "decimal", "declare", "decrement", "default", "defaults", "define",
                  "delete", "delimiter", "desc", "difference", "distinct", "divide", "do", "double", "drop", "else",
                  "empty", "encoding", "end", "equals", "escape", "exclusive", "exec", "execute", "exists", "explain",
                  "false", "fetch", "file", "field", "first", "float", "for", "from", "function", "go", "goto", "grant",
                  "greater", "group", "having", "identified", "if", "immediate", "in", "increment", "index", "initial",
                  "inner", "inout", "input", "insert", "int", "integer", "intersect", "intersection", "into", "is",
                  "isempty", "isnull", "join", "last", "left", "less", "like", "limit", "lock", "long", "max", "min",
                  "minus", "mode", "modify", "modulo", "more", "multiply", "next", "noaudit", "not", "notin", "nowait",
                  "null", "number", "object", "of", "on", "option", "or", "order", "outer", "output", "power",
                  "previous", "prior", "privileges", "public", "raise", "raw", "remainder", "rename", "resource",
                  "return", "returns", "revoke", "right", "row", "rowid", "rownum", "rows", "select", "session", "set",
                  "share", "size", "sqrt", "start", "strict", "string", "subtract", "sum", "synonym", "table", "then",
                  "to", "trans", "transaction", "trigger", "true", "uid", "union", "unique", "update", "user",
                  "validate", "values", "view", "when", "whenever", "where", "while", "with"]


def get_config(config):
    try:
        if config is not None:
            jira_server_url = config.get('server_url')
            jira_username = config.get('username')
            jira_token = config.get('token')
            verify_ssl = config.get('verify_ssl')
            authentication = config.get('authentication')
            return jira_server_url, jira_username, authentication, jira_token, verify_ssl
    except Exception as Err:
        logger.warn('Error occured while extracting conf :[{0}] '.format(Err))
        raise ConnectorError(Err)


def make_api_call(config, method, endpoint=None, json=None, headers=None, files=None, params=None, data=None):
    server = config.get('server_url') or ''
    verify_ssl = config.get('verify_ssl')
    auth_type = _auth_type(config)
    if server.startswith('https://'):
        server = server.strip('/')
    else:
        if not server.startswith('http://'):
            server = 'https://{0}'.format(server)
    if not headers:
        headers = {'content-type': 'application/json', 'accept': 'application/json'}
    url = '{0}{1}'.format(server, endpoint) if endpoint else server

    auth = None
    if auth_type == CLOUD_AUTH:
        username = config.get('username') or ''
        token = config.get('token') or ''
        encoded = b64encode('{0}:{1}'.format(username, token).encode('utf-8')).decode('utf-8')
        headers['Authorization'] = 'Basic {0}'.format(encoded)
        auth = (username, token)
    elif auth_type == SERVER_BASIC_AUTH:
        username = config.get('username') or ''
        password = config.get('password') or ''
        encoded = b64encode('{0}:{1}'.format(username, password).encode('utf-8')).decode('utf-8')
        headers['Authorization'] = 'Basic {0}'.format(encoded)
        auth = (username, password)
    elif auth_type == SERVER_PAT_AUTH:
        pat = config.get('pat') or ''
        headers['Authorization'] = 'Bearer {0}'.format(pat)
    else:
        raise ConnectorError('Unsupported Authentication Type: {0}'.format(auth_type))

    logger.info('Request URL {}'.format(url))
    try:
        response = requests.request(method=method, url=url, auth=auth, headers=headers, files=files,
                                    data=json, params=params, verify=verify_ssl)
        if response.ok:
            return response
        elif response.status_code == 401:
            logger.info('Unauthorized: Invalid credentials')
            raise ConnectorError('Unauthorized: Invalid credentials')
        else:
            logger.info(
                'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url), str(response.content),
                                                                                    str(response.reason)))
            raise ConnectorError(
                'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url), str(response.content),
                                                                                   str(response.reason)))
    except requests.exceptions.SSLError as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format('SSL certificate validation failed'))
    except requests.exceptions.ConnectionError as e:
        logger.exception('{}'.format(e))
        raise ConnectorError(
            '{} : {}'.format('The request timed out while trying to connect to the remote server', url))
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def check_health(config):
    try:
        projects = list_projects(config, None)
        logger.debug('Health Check: {}'.format(projects))
        if len(projects['values']) > 0:
            return True
        else:
            logger.exception(
                'Error occurred while connecting to server, check credentials and make sure you have at least one JIRA project')
            raise ConnectorError(
                'Error occurred while connecting to server, check credentials and make sure you have at least one JIRA project')
    except Exception as Err:
        logger.exception('Error occurred while connecting to server: {0}'.format(str(Err)))
        raise ConnectorError('Error occurred while connecting to server: {0}'.format(Err))


def check_payload(payload):
    payload1 = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                payload1[key] = nested
        elif value:
            payload1[key] = value
    return payload1


def create_ticket(config, params, **kwargs):
    try:
        project_key = params.get('project_key')
        ticket_summary = params.get('ticket_summary')
        ticket_description = params.get('ticket_description')
        issue_type = params.get('issue_type')
        priority = params.get('priority')
        other_fields = params.get('other_fields')
        body = {
            "fields": {
                "project": {
                    "key": project_key
                },
                "summary": ticket_summary,
                "description": _description_body(ticket_description, config),
                "issuetype": {
                    "name": issue_type
                },
                "priority": {
                    "name": priority
                }
            }
        }
        if other_fields:
            body['fields'].update(other_fields)
        if params.get('parent'):
            parent_body = {
                "parent": {"key": params.get('parent')}
            }
            body['fields'].update(parent_body)
        payload1 = check_payload(body)
        response = make_api_call(config, method='POST', endpoint=_issue_endpoint(config), json=json.dumps(payload1))
        if response.ok:
            contents = json.loads(response.content.decode('UTF-8'))
            key_id = contents['key']
            param = {'issue_key': key_id}
            result = get_ticket_details(config, param)
            if result:
                issue_status = result['fields']['status']['name']
                contents.update({"status": issue_status})
            return contents
        else:
            raise ConnectorError('Error [{0}] occurred while creating jira ticket with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def get_ticket_details(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        endpoint = "{0}{1}".format(_issue_endpoint(config), issue_key)
        response = make_api_call(config, method='GET', endpoint=endpoint)
        logger.info('Returning ticket status response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while fetching jira ticket status with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def update_ticket(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        project_key = params.get('project_key')
        summary = params.get('summary')
        description = params.get('description')
        comment = params.get('comment')
        if comment:
            comment = _comment_add_body(comment, config)
        priority = params.get('priority')
        status = params.get('status')
        other_fields = params.get('other_fields')
        if status:
            transition_endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key,
                                                     '/transitions?expand=transitions.fields')
            transition_response = make_api_call(config, method='GET', endpoint=transition_endpoint)
            transitions = json.loads(transition_response.content.decode('UTF-8'))
            id = [item['id'] for item in transitions['transitions'] if item['to']['name'] == status]
            if len(id) == 0:
                raise ConnectorError('The Status given is invalid')
            body = {
                "transition": {
                    "id": id[0]
                }
            }
            endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key,
                                          '/transitions?expand=transitions.fields')
            status_response = make_api_call(config, method='POST', endpoint=endpoint, json=json.dumps(body))
        body = {
            "update": {
                "comment": [
                    {
                        "add": {
                            "body": comment
                        }
                    }
                ]
            },
            "fields": {
                "project": {
                    "key": project_key
                },
                "summary": summary,
                "description": _description_body(description, config),
                "priority": {"name": priority}
            }
        }
        if other_fields:
            body['fields'].update(other_fields)
        endpoint = "{0}{1}".format(_issue_endpoint(config), issue_key)
        payload1 = check_payload(body)
        response = make_api_call(config, method='PUT', endpoint=endpoint, json=json.dumps(payload1))
        logger.info('Returning update ticket response : [{0}]'.format(response))
        if response.ok:
            return {"status": "Success", "message": "Ticket updated successfully"}
        else:
            raise ConnectorError('Error [{0}] occurred while updating jira ticket with status : [{1}] code'.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def _get_file_data(iri_type, iri):
    try:
        file_name = None
        if iri_type == 'Attachment ID':
            if not iri.startswith('/api/3/attachments/'):
                iri = '/api/3/attachments/{0}'.format(iri)
            attachment_data = make_request(iri, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
        else:
            file_iri = iri
        file_download_response = download_file_from_cyops(file_iri)
        if not file_name:
            file_name = file_download_response['filename']
        file_path = join('/tmp', file_download_response['cyops_file_path'])
        logger.error('file id = %s, file_name = %s' % (file_iri, file_name))
        return file_name, file_path
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError('could not find attachment with id {}'.format(str(iri)))


def submit_file(config, params, **kwargs):
    issue_key = params.get('issue_key')
    endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key, '/attachments')
    iri_type = params.get('path')
    iri = params.get('value')
    file_name, file_path = _get_file_data(iri_type, iri)
    with open(file_path, 'rb') as attachment:
        file_data = attachment.read()
    files = {'file': (file_name, file_data)}
    headers = {'X-Atlassian-Token': 'no-check'}
    submit_file = make_api_call(config, method='POST', endpoint=endpoint, files=files, headers=headers)
    if submit_file:
        return submit_file.json()
    raise ConnectorError("Failed to Submit file. ", submit_file)


def add_remote_link(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key, '/remotelink')
        payload = {
            "object": {
                "url": params.get('url'),
                "title": params.get('title')
            }
        }
        payload1 = check_payload(payload)
        response = make_api_call(config, method='POST', endpoint=endpoint, json=json.dumps(payload1))
        logger.info('Returning link ticket response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while creating link to jira ticket with status : [{1}] code '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def add_comment(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        comment = params.get('comment')
        body = {"body": _description_body(comment, config)}
        endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key, '/comment')
        response = make_api_call(config, method='POST', endpoint=endpoint, json=json.dumps(body))
        logger.info('Returning comment ticket response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while adding comment to jira ticket with status : [{1}] code '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def get_comments(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        orderBy = params.get('orderBy')
        if orderBy:
            if orderBy == 'Ascending':
                orderBy = 'created'
            else:
                orderBy = '-created'
        payload = {
            "startAt": params.get('startAt'),
            "maxResults": params.get('maxResults'),
            "orderBy": orderBy
        }
        endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key, '/comment')
        payload = {k: v for k, v in payload.items() if v is not None and v != ''}
        response = make_api_call(config, method='GET', endpoint=endpoint, params=payload)
        logger.info('Returning comment ticket response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while getting comments from jira with status : [{1}] code '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def delete_ticket(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        delete_subtask = params.get('delete_subtask')
        endpoint = "{0}{1}".format(_issue_endpoint(config), issue_key)
        endpoint_issue_info = "{0}{1}".format(_issue_endpoint(config), issue_key)
        response_issue_info = make_api_call(config, method='GET', endpoint=endpoint_issue_info)
        logger.info('Returning ticket status response : [{0}]'.format(response_issue_info))
        if response_issue_info.ok:
            issue_info = response_issue_info.json()
            subtask = issue_info['fields']['subtasks']
            if len(subtask) > 0 and delete_subtask == False:
                raise ConnectorError("Issue has Subtasks, cannot be deleted")
            elif delete_subtask == True or (len(subtask) == 0 and delete_subtask == False):
                response = make_api_call(config, method='DELETE', endpoint=endpoint)
                if response.ok:
                    return {"status": "Success", "message": "Ticket deleted successfully"}
                else:
                    raise ConnectorError('Error [{0}] occurred while deleting jira ticket with status : [{1}] code'.
                                         format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def list_projects(config, params, **kwargs):
    try:
        endpoint = '/rest/api/{0}/project/search'.format(_api_version(config))
        response = make_api_call(config, method='GET', endpoint=endpoint)
        logger.info('Returning Project lists response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while fetching jira ticket status with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def list_tickets(config, params, **kwargs):
    try:
        jql_query = params.get('jql_query')
        maxResults = params.get('maxResults')
        nextPageToken = params.get('nextPageToken')
        fields = params.get('fields')
        if not fields:
            fields = []
        else:
            if not isinstance(fields, list):
                fields = fields.split(",")
        endpoint = _search_jql_endpoint(config)
        project_key = re.search(r"project\s?=\s?(\w+)", jql_query)
        if project_key is None:
            raise ConnectorError(
                'Project ID is not defined properly in the JQL query, make sure to use the syntax: project = YOUR_PROJECT_ID')
        project_key = project_key.group(1)

        if project_key.lower() in reserved_words:
            jql_query = jql_query.replace(project_key, '"' + project_key + '"')
        start_datetime = params.get('start_time')
        if start_datetime:
            start_date = start_datetime.split("T")
            start_time = start_date[1].split(".")
            start_datetime = start_date[0] + " " + start_time[0][:-3]
            jql_query = jql_query + " and created >= '{0}' or updated >= '{1}'".format(start_datetime, start_datetime)
        logger.info('Running JQL query:{}'.format(jql_query))
        body = {
            "jql": jql_query,
            "maxResults": maxResults,
            "nextPageToken": nextPageToken,
            "fields": fields
        }
        payload = {k: v for k, v in body.items() if v is not None and v != ''}
        response = make_api_call(config, method='POST', endpoint=endpoint, json=json.dumps(payload))
        logger.info('Returning Ticket lists response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while fetching jira ticket status with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def validate_jql_query(config, params, **kwargs):
    try:
        # /jql/parse only exists on Cloud (v3); Server / DC has no equivalent.
        if not _is_cloud(config):
            raise ConnectorError("'JQL parse' is supported only on Jira Cloud (REST v3). Your configured deployment is Server / Data Center.")
        endpoint = '/rest/api/3/jql/parse'
        jql_query = params.get('jql_query')
        payload = {
            "queries": [jql_query]
        }
        response = make_api_call(config, method='POST', endpoint=endpoint, json=json.dumps(payload))
        logger.info('Returning JQL Query Validation response : [{0}]'.format(response))
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while validating JQL query with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def search_users(config, params, **kwargs):
    try:
        # Cloud: /users/search returns all users; Server / DC: /user/search requires a query param.
        endpoint = '/rest/api/3/users/search' if _is_cloud(config) else '/rest/api/2/user/search'
        url_params = {
            'startAt': params.get('startAt', 0),
            'maxResults': params.get('maxResults', 50)
        }
        response = make_api_call(config, method='GET', endpoint=endpoint, params=url_params)
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while searching users with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def get_user_details(config, params, **kwargs):
    try:
        endpoint = '/rest/api/{0}/user'.format(_api_version(config))
        url_params = {
            'accountId': params.get('accountId'),
            'expand': 'groups,applicationRoles'
        }
        response = make_api_call(config, method='GET', endpoint=endpoint, params=url_params)
        if response.ok:
            return response.json()
        else:
            raise ConnectorError('Error [{0}] occurred while searching user details with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def assign_issue(config, params, **kwargs):
    try:
        accountId = params.get('accountId', None)
        issue_key = params.get('issue_key')
        endpoint = '/rest/api/{0}/issue/{1}/assignee'.format(_api_version(config), issue_key)
        payload = {
            'accountId': accountId
        }
        response = make_api_call(config, method='PUT', endpoint=endpoint, json=json.dumps(payload))
        logger.info('Assigning Issue : [{0}] to user [{1}]'.format(issue_key, accountId))
        if response.status_code == 204:
            return {'message': 'Issue : [{0}] assigned to user [{1}]'.format(issue_key, accountId)}
        else:
            raise ConnectorError('Error [{0}] occurred while assigning issue with status [{1}] code : '.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def set_status(config, params, **kwargs):
    try:
        issue_key = params.get('issue_key')
        status = params.get('status')
        transition_endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key,
                                                 '/transitions?expand=transitions.fields')
        transition_response = make_api_call(config, method='GET', endpoint=transition_endpoint)
        transitions = json.loads(transition_response.content.decode('UTF-8'))
        id = [i['id'] for i in transitions['transitions'] if i['name'] == status]
        if len(id) == 0:
            raise ConnectorError('The Status given is invalid')
        body = {
            "transition": {
                "id": id[0]
            }
        }
        payload1 = check_payload(body)
        endpoint = "{0}{1}{2}".format(_issue_endpoint(config), issue_key, '/transitions?expand=transitions.fields')
        response = make_api_call(config, method='POST', endpoint=endpoint, json=json.dumps(payload1))
        logger.info('Returning update ticket response : [{0}]'.format(response))
        if response.ok:
            return {"status": "Success", "message": "Ticket status updated successfully"}
        else:
            raise ConnectorError('Error [{0}] occurred while updating jira ticket with status : [{1}] code'.
                                 format(response.reason, response.status_code))
    except Exception as Err:
        raise ConnectorError(Err)


def get_basic_auth_token(iri, username, password):
    global headers
    data = {"credentials": {"loginid": username, "password": password, "token": ""}}
    auth_url = iri + "/auth/authenticate"
    response = requests.post(auth_url, json=data, verify=False)
    if response.status_code == 200:
        return response.json()['token']
    else:
        return str(auth_url + ' Error in post request ' + str(response.status_code))


def update_fortisoar(config, params, **kwargs):
    env = kwargs["env"]
    data = env["request"]["data"]
    jira_mapping_status = env["jira_mapping_status"]
    jira_mapping_priority = env["jira_mapping_priority"]
    cyops_url = env['request']['baseUri']
    jira_key = params.get('jira_key')
    cyops_username = params.get('cyops_username')
    cyops_password = params.get('cyops_password')

    jira_priority = data['issue']['fields']['priority']['name']
    jira_status = data['issue']['fields']['status']['name']
    jira_summary = data['issue']['fields']['summary']

    # Authentication
    headers = get_basic_auth_token(cyops_url, cyops_username, cyops_password)
    request_headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + headers
    }
    url = cyops_url + '/api/3/incidents?sourceid={}'.format(jira_key)
    result = requests.get(url, headers=request_headers, verify=False)
    json_result = json.loads(result.content.decode('UTF-8'))
    incident_id = json_result['hydra:member'][0]['@id']
    incident_priority_list = json_result['hydra:member'][0]['jiraPriority']
    incident_priority = ""
    if incident_priority_list:
        incident_priority = incident_priority_list['@id']
    incident_status = ""
    incident_status_list = json_result['hydra:member'][0]['jiraStatus']
    if incident_status_list:
        incident_status = incident_status_list['@id']
    incident_name = json_result['hydra:member'][0]['name']
    inc_url = cyops_url + incident_id
    update_result = {}
    # Update Incident
    try:
        jira_status_id = data['issue']['fields']['status']['id']
        if str(jira_status_id) in jira_mapping_status.keys():
            id = jira_mapping_status[jira_status_id]
        else:
            id = jira_mapping_status[jira_status]
        if jira_mapping_priority[
            jira_priority] != incident_priority or id != incident_status or jira_summary != incident_name:
            payload = {"jiraStatus": id, "jiraPriority": jira_mapping_priority[jira_priority]}
            update_result = requests.put(inc_url, data=json.dumps(payload), headers=request_headers, verify=False)
            return json.loads(update_result.content.decode('UTF-8'))
        return update_result
    except Exception as e:
        raise ConnectorError(e)


operations = {
    'create_ticket': create_ticket,
    'get_ticket_details': get_ticket_details,
    'list_projects': list_projects,
    'list_tickets': list_tickets,
    'validate_jql_query': validate_jql_query,
    'search_users': search_users,
    'get_user_details': get_user_details,
    'assign_issue': assign_issue,
    'submit_file': submit_file,
    'add_remote_link': add_remote_link,
    'add_comment': add_comment,
    'get_comments': get_comments,
    'set_status': set_status,
    'update_ticket': update_ticket,
    'update_fortisoar': update_fortisoar,
    'delete_ticket': delete_ticket
}
