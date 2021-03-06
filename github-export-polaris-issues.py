#!/usr/bin/python

import re
import linecache
import sys
import requests
import json
import jsonapi_requests
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlparse
import sys
import os
import argparse
import urllib
import glob

from github import Github

MAX_LIMIT = 500

def configApi(url):
    return jsonapi_requests.Api.config({
        'API_ROOT': url + '/api',
        'AUTH': jwtAuth(),
        'TIMEOUT': 100
    })

class jwtAuth(requests.auth.AuthBase):
    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer ' + token
        return r

def printError(e):
    content = e.content.decode("utf-8")
    content = json.loads(content)
    print("FATAL: Error Code " + str(e.status_code) + ": " + content['errors'][0]['detail'])
    sys.exit(2)

def getJwt(url, token, email=None, password=None):
    apiRoot = url + '/api/auth/v1'
    api = jsonapi_requests.Api.config({
        'API_ROOT': apiRoot,
        'TIMEOUT': 100
    })
    endpoint = api.endpoint('authenticate')
    auth_headers = { 'Content-Type' : 'application/x-www-form-urlencoded' }
    if token != None:
        auth_params = { 'accesstoken' : token }
    else:
        auth_params = { 'email' : email, 'password' : password }

    try:
        response = endpoint.post(headers=auth_headers, data=auth_params)
    except jsonapi_requests.request_factory.ApiClientError as e:
        printError(e)
    return response.payload['jwt']

def printCurl(ep, method, limit=MAX_LIMIT, params=None, data=None):
    # prints out curl representation
    command = "curl -v -g -X {method} {uri} -H {headers}"
    headers = {'Authorization': 'Bearer ' + token}
    header_list = ['"{0}: {1}"'.format(k, v) for k, v in headers.items()]
    header = " -H ".join(header_list)
    path = ep.path
    url = ep.requests.config.API_ROOT + path
    if params:
        if 'page[limit]' not in params:
            params['page[limit]'] = str(limit)
        param_list = ['"{0}={1}"'.format(k, v) for k, v in params.items()]
        param_str = "&".join(param_list).replace('"','')
        # Remove spaces from 'include[issue][]': ['severity', 'related-indicators', 'related-taxa']
        param_str = param_str.replace(' ', '')
        url = url + '?' + param_str
    url = '"' + url + '"'
    if data:
        command = "curl -v -g -X {method} {uri} -H {headers} -D \"{data}\""
        print(command.format(method=method, headers=header, uri=url, data=data))
    else:
        print(command.format(method=method, headers=header, uri=url))

def getPaginatedData(endpoint, params, limit=MAX_LIMIT):
    offset = 0
    total = limit + 1
    data = []
    included = []

    params['page[limit]'] = str(limit)
    params['page[offset]'] = str(offset)

    while (offset < total):
        try:
            response = endpoint.get(params=params)
        except jsonapi_requests.request_factory.ApiClientError as e:
            printError(e)
        if (debug >= 7): print(response)

        if (response.payload['data'] == []):
            # Return empty list (or 2 empty lists for issues endpoint)
            p = re.compile(r'query\/v\d+\/issues')
            if p.match(endpoint.path):
                return [], []
            else:
                return []

        # we actually only need to fetch total once
        total = response.payload['meta']['total']

        data.extend(response.payload['data'])
        try: included.extend(response.payload['included'])
        except: pass

        # update the offset to the next page
        offset += limit
        params['page[offset]'] = str(offset)

        # if limit is less than MAX_LIMIT, assume we are after the first N records
        if (limit < MAX_LIMIT): break

    if (included == []): return data
    else: return data, included

def getRuns(projectId, branchId, limit=MAX_LIMIT, getCheckers=False):
    endpoint = api.endpoint('common/v0/runs')
    params = dict([
        ('filter[run][project][id][eq]', projectId ),
        ('filter[run][revision][branch][id][eq]', branchId),
        ])
    if (debug >= 3): printCurl(endpoint, 'GET', limit, params)
    runs = getPaginatedData(endpoint, params, limit)
    if runs == []:
        return []

    # loop over the list of runs and grab the fields we want to include in the dictionary
    dictionary = []
    timeFormat = '%Y-%m-%dT%H:%M:%S.%fZ'
    for run in runs:
        runId = run['id']
        status = run['attributes']['status']
        dateCreated = run['attributes']['creation-date']
        dateCompleted = run['attributes']['completed-date']
        uploadId = run['attributes']['upload-id']
        projectId = run['relationships']['project']['data']['id']
        revisionId = run['relationships']['revision']['data']['id']
        toolId = run['relationships']['tool']['data']['id']
        submitting_userId = run['relationships']['submitting-user']['data']['id']
        submitting_orgId = run['relationships']['submitting-organization']['data']['id']
        if (getCheckers): checkers = ' '.join(getRunProperties(runId, limit))
        else: checkers = ''

        try: previous_runId = run['relationships']['previous-run']['data']['id']
        except: previous_runId = None

        entry = {
            'runId': runId,
            'status': status,
            'dateCreated': dateCreated,
            'dateCompleted': dateCompleted,
            'uploadId': uploadId,
            'projectId': projectId,
            'revisionId': revisionId,
            'toolId': toolId,
            'submitting_userId': submitting_userId,
            'submitting_orgId': submitting_orgId,
            'previous_runId': previous_runId,
            'checkers': checkers,
        }

        if (debug >= 5): print(entry)
        dictionary.append(entry)

    return dictionary

def getEventsWithSource(url, headers, findingId, runId):
    endpoint = url + '/api/code-analysis/v0/events-with-source'
    filterPath = ""
    params = dict([
        ('run-id',runId),
        ('finding-key',findingId),
        ('occurrence-number',1),
        ('filter-path',filterPath),
        ('max-depth',10),
        ('Accept-Language','en')
        ])

    r = requests.get(endpoint, headers=headers, params=params )

    if r.status_code == 200:
      return r.json()['data'][0]
    else:
      print(f"ERROR: Unable to get events with source for findingId={findingId} in runId={runId}: Error code   {r.status_code}")
      print(r.text)
      return None

def getSource(url, headers, runId, path):
    if (globals.debug): print("DEBUG: getSource(" + url + ", headers, " + runId + ", " + path + ")")
    endpoint = url + '/api/code-analysis/v0/source-code'
    params = dict([
        ('run-id',runId),
        ('path',path)
        ])

    r = requests.get(endpoint, headers=headers, params=params )

    if r.status_code != 200:
      print(f"ERORR: Unable to get source code for path={path} and runId={runId}: Error code {r.status_code}")
      print(r.text)

    return r.text

def getIssues(projectId, branchId, runId, limit=MAX_LIMIT, filter=None, triage=False, events=False, source=False, codeFlows=False):
    dictionary = []
    issues_data = []
    issues_included = []
    issues_start = datetime.now()
    triage_total_es = 0.0
    events_total_es = 0.0
    closed_date = None

    endpoint = api.endpoint('query/v1/issues')
    params = dict([
        ('project-id', str(projectId)),
        ('include[issue][]', ['severity', 'related-indicators', 'related-taxa'])
        ])

    # filter by runId or branchId but not both
    if runId is not None: params['run-id[]'] = str(runId)
    else: params['branch-id'] = str(branchId)

    # update params with optional user-specified filter
    if filter:
        params.update(filter)

    if (debug >= 3): printCurl(endpoint, 'GET', limit, params)
    issues_data, issues_included = getPaginatedData(endpoint, params, limit)
    if issues_data == []:
        return []

    # Create the base url so we can build an issue url later
    # branchId is not guaranteed to be known here, so that is added later during issue processing
    baseUrl = issues_data[0]['links']['self']['href']
    data = urlparse(baseUrl)
    baseUrl = data.scheme + '://' + data.netloc
    baseUrl += '/projects/' + projectId

    timeFormat = '%Y-%m-%dT%H:%M:%S'

    # loop over the list of issues
    for issue in issues_data:

        issueKey = issue['attributes']['issue-key']
        findingKey = issue['attributes']['finding-key']
        checker = issue['attributes']['sub-tool']
        issue_type_id = issue['relationships']['issue-type']['data']['id']
        issue_path_id = issue['relationships']['path']['data']['id']
        try: severity = issue['relationships']['severity']['data']['id']
        except: severity = None

        # [0] = first detected
        # [1] = fixed by code change
        # TODO - what happens if issue is re-introduced, etc? can there be more elements
        issue_opened_id = issue['relationships']['transitions']['data'][0]['id']
        try: issue_closed_id = issue['relationships']['transitions']['data'][1]['id']
        except: issue_closed_id = None

        cwe = None
        try:
            # There can be several CWEs, so merge them all in to a single string
            for taxa_data in issue['relationships']['related-taxa']['data']:
                if cwe is None:
                    cwe = taxa_data['id']
                else:
                    cwe += "," + taxa_data['id']
        except: cwe = None

        indicators = None
        if issue['relationships']['related-indicators']['data']:
            # TODO just pull the id values as a straight list
            indicator_list = []
            for ind_dct in issue['relationships']['related-indicators']['data']:
                for ind_key, val in ind_dct.items():
                    if ind_key == 'id':
                        indicator_list.append(val)
            indicators = ','.join(indicator_list)

        # iterate through included to get name, description, local-effect, issue-type
        for issue_included in issues_included:
            if issue_included['id'] == issue_type_id:
                # check for type "issue-type"? Is id unique?
                try: name = issue_included['attributes']['name']
                except: name = None
                try: description = issue_included['attributes']['description']
                except: description = None
                try: local_effect = issue_included['attributes']['local-effect']
                except: local_effect = None
                try: type = issue_included['attributes']['issue-type']
                except: type = None

            if issue_included['id'] == issue_path_id:
                dirsep = '/'
                try: path = dirsep.join(issue_included['attributes']['path'])
                except: path = None

            if issue_included['id'] == issue_opened_id:
                # TODO should we check for issue_included['type'] == 'transition'??
                first_detected = datetime.strptime( \
                   issue_included['attributes']['transition-date'].split('.')[0], \
                   timeFormat)

                # NOTE: state/cause stored here are the first detected state/cause
                #  -- not necessarily _current state_ of the issue.
                state = issue_included['attributes']['transition-type']
                cause = issue_included['attributes']['human-readable-cause']
                branchId = issue_included['attributes']['branch-id']
                revisionId = issue_included['attributes']['revision-id']

                # Construct issue URL
                url = baseUrl + '/branches/' + branchId
                url += '/revisions/'
                url += revisionId
                url += '/issues/' + issueKey

            if issue_closed_id and issue_included['id'] == issue_closed_id:
                closed_date = datetime.strptime( \
                  issue_included['attributes']['transition-date'].split('.')[0], \
                  timeFormat)
            else:
                closed_date = None
        if triage:
            triage_start = datetime.now()
            triage_owner = None
            triage_status = None
            triage_comment = None
            triage_jira_ticket = None

            # TODO - add getTriageCurrent and use it instead
            triage_data = getTriageHistory(issueKey, projectId)
            if triage_data:
                comments = []
                for triage in reversed(triage_data): # go through all history updates from oldest to latest
                    timestamp = triage['attributes']['timestamp'].split('.')[0]
                    timestamp = datetime.strptime(timestamp, timeFormat)
                    # TODO replace for-loop with python dict['key'='value'] code
                    for triage_hist_value in triage['attributes']['triage-history-values']:
                        if triage_hist_value['attribute-semantic-id'] == 'OWNER':
                            triage_userid = triage_hist_value['value']
                            triage_owner = getUserById(triage_userid)['data']['attributes']['name']
                        elif triage_hist_value['attribute-semantic-id'] == 'COMMENTARY':
                            if  triage_hist_value['display-value'].startswith('JIRA ticket:'):
                                triage_jira_ticket = triage_hist_value['display-value'][len('JIRA ticket:')] # Jira ticket url should be first
                            if timestamp:
                                comments.append(str(timestamp) + ' ' + triage_hist_value['display-value'])
                            else:
                                comments.append(triage_hist_value['display-value'] )
                        # TODO - API is stuffing triage status into the Dismiss attribute, this may change
                        elif triage_hist_value['attribute-name'] == 'Dismiss':
                            triage_status = triage_hist_value['display-value']
                            if triage_status.startswith('Dismissed'):
                                closed_date = timestamp
                if comments:
                    triage_comment = ']\n['.join(comments)
                    triage_comment = '[' + triage_comment + ']'

            # create the dictionary entry
            triage_dct = {
                'owner': triage_owner, 'comment': triage_comment, \
                'status': triage_status, 'jira': triage_jira_ticket
                 }
            triage_end = datetime.now()
            triage_total = triage_end - triage_start
            triage_total_es += triage_total.total_seconds()

        if source:
            headers = {'Authorization': 'Bearer ' + token,
                       'Accept-Language': 'en'}

            event_tree = getEventsWithSource(os.getenv("POLARIS_URL"), headers, findingKey, runId)

            if (event_tree == None):
                if (debug): print("DEBUG: Issue " + findingKey + " not found in run " + runId + ", skipping")
                continue
            else:
                if (debug): print("DEBUG: Issue " + findingKey + " found in run " + runId)

            events = event_tree['events']

            main_file = event_tree['main-event-file-path'][-1]
            main_loc = str(event_tree['main-event-line-number'])

            print(json.dumps(issue, indent = 4, sort_keys=True))
            ticket_body = ""
            #         # iterate through included to get name, description, local-effect, issue-type
            ticket_body = ticket_body + "### Coverity - " + name + " (CWE " + cwe + ") in    " +  main_file + "\n"
            ticket_body = ticket_body + description + " " + local_effect + "\n"
            fd = str(first_detected) + "\n"
            ticket_body = ticket_body + "The issue was first detected on " + fd + "\n"
            ticket_body = ticket_body + "\n"

            currentFile = ""
            for event in events:
                eventNumber = str(event['event-number'])
                if (event['path'][-1] == currentFile):
                    currentFile = event['path'][-1]
                else:
                    ticket_body = ticket_body + "From " + event['path'][-1] + ": \n"
                    currentFile = event['path'][-1]
                currentFile = event['path'][-1]
                if (debug): print("DEBUG: Event " + event['event-tag'] + " #" + eventNumber + " in " + event['filePath'])

                if ('source-before' in event and event['source-before']):
                    separate_lines = event['source-before']['source-code'].splitlines()
                    ticket_body = ticket_body + "```\n"
                    current_line_no = event['source-before']['start-line']
                    for line in separate_lines:
                        pre_line = "%5d %s\n" % (current_line_no, line)
                        current_line_no = current_line_no + 1
                        ticket_body = ticket_body + pre_line
                    ticket_body = ticket_body + "\n```\n"
                if (event['event-type'] == "MAIN"):
                    ticket_body = ticket_body + "<span style=\"color:red\">" + "**" + "#" + eventNumber + ":    " + event['event-tag'] + ": " + event['event-description'] + "**" + "</span>\n"
                elif (event['event-tag'] == "remediation"):
                    ticket_body = ticket_body + "**" + "#" + eventNumber + ": " + event['event-tag'] + ": " + event['event-description'] + "**" + "\n"
                else:
                    ticket_body = ticket_body + "**" + "#" + eventNumber + ": " + event['event-tag'] + ": " + event['event-description'] + "**\n\n"
                if ('source-after' in event and event['source-after']):
                    separate_lines = event['source-after']['source-code'].splitlines()
                    ticket_body = ticket_body + "```\n"
                    current_line_no = event['source-after']['start-line']
                    for line in separate_lines:
                        pre_line = "%5d %s\n" % (current_line_no, line)
                        current_line_no = current_line_no + 1
                        ticket_body = ticket_body + pre_line
                    ticket_body = ticket_body + "\n```\n"

            if (debug): print("DEBUG: ticket body=\n" + ticket_body)

            source_dct = {'markdown_comment': ticket_body}

        if events:
            events_start = datetime.now()
            # Added to grab line numbers as well
            endpoint = api.endpoint('code-analysis/v0/events')
            params = dict([('finding-key', str(findingKey)),
                ('run-id', str(runId)),
                ('locator-path', str(path))
                ])
            headers = {'Authorization': 'Bearer ' + token,
                'Accept-Language': 'en'}

            main_event_dct = dict()
            remediation_dct = dict()
            if (debug >= 3): printCurl(endpoint, 'GET', limit, params)
            try:
                response = endpoint.get(params=params, headers=headers)
                # JC: Look for remediation advice
                data = response.payload['data'][0]
                events = data['events']
                threadFlows = []
                for event in events:
                    if (event['event-tag'] == 'remediation'):
                        remediation = event['event-description']
                        remediation_dct = {'remediation': remediation}
                    if (event['event-type'] == "MAIN"):
                        main_event = event['event-description']
                        main_event_dct = {'main_event': main_event}
                    # Also format codeflows
                    if codeFlows:
                        threadFlow = {
                            "file": event['filePath'],
                            "line": event['line-number'],
                            "message": f"Event #{event['event-number']} {event['event-tag']}: {event['event-description']}"
                        }
                        threadFlows.append(threadFlow)

                if codeFlows:
                    code_flow_dct = {'codeFlows': threadFlows }

                line = response.payload['data'][0]['main-event-line-number']
            except jsonapi_requests.request_factory.ApiClientError as e:
                printError(e)
            line_dct = {'line': line}
            events_end = datetime.now()
            events_total = events_end - events_start
            events_total_es += events_total.total_seconds()
        age = datetime.utcnow() - first_detected
        if (closed_date is not None): ttr = closed_date - first_detected
        else: ttr = first_detected - first_detected

        # create the dictionary entry
        entry = {'projectId': projectId, 'branchId': branchId, \
             'issue-key': issueKey, 'finding-key': findingKey, \
             'checker': checker, 'severity': severity, \
             'type': type, 'local_effect': local_effect, 'name': name, \
             'description': description, 'path': path, \
             'first_detected': first_detected , 'url': url, \
             'state' : state, 'cause' : cause, 'cwe' : cwe, \
             'indicators' : indicators, \
             'branchId' : branchId, 'revisionId' : revisionId, \
             'closed_date': str(closed_date), \
             'age': age, 'ttr': ttr
             }
        if triage:
            entry.update(triage_dct)
        if events:
            entry.update(line_dct)
            entry.update(remediation_dct)
            entry.update(main_event_dct)
        if source:
            entry.update(source_dct)
        if codeFlows:
            entry.update(code_flow_dct)

        if (debug >= 5): print(entry)
        dictionary.append(entry)

    if (debug >= 1):
        issues_total = datetime.now() - issues_start
        issues_total_secs = issues_total.total_seconds()
        print('total getIssues elapsed time: ' + str(issues_total_secs))
        if triage:
            print('total triage elapsed time:' + str(triage_total_es))
        if events:
            print('total events elapsed time:' + str(events_total_es))
    return dictionary

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Post Coverity issue summary to GitLab CI Notes Object')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
args = parser.parse_args()

debug = int(args.debug)

# Process output from Polaris CLI
with open(".synopsys/polaris/cli-scan.json") as f:
  polaris_output = json.load(f)

if (debug): print(f"DEBUG: CLI Scan data:" + json.dumps(polaris_output, indent = 4, sort_keys=True) + "\n")

issueApiUrl = polaris_output['scanInfo']['issueApiUrl']
projectId = polaris_output['projectInfo']['projectId']
branchId = polaris_output['projectInfo']['branchId']
summaryUrl = polaris_output['issueSummary']['summaryUrl']

polaris_url = os.getenv("POLARIS_URL")
polaris_access_token = os.getenv("POLARIS_ACCESS_TOKEN")

if (polaris_url == None or polaris_access_token == None):
    print(f"ERROR: Must specifcy POLARIS_URL and POLARIS_ACCESS_TOKEN")
    sys.exit(1)

token = getJwt(polaris_url, polaris_access_token)
api = configApi(polaris_url)

print(f"INFO: Fetching issues for project {projectId}")

runs = getRuns(projectId, branchId)
latest_run = runs[0]

runId = latest_run['runId']

issues = getIssues(projectId, branchId, runId, events=True, source=True, codeFlows=True)

#        entry = {'projectId': projectId, 'branchId': branchId, \
#             'issue-key': issueKey, 'finding-key': findingKey, \
#             'checker': checker, 'severity': severity, \
#             'type': type, 'local_effect': local_effect, 'name': name, \
#             'description': description, 'path': path, \
#             'first_detected': first_detected , 'url': url, \
#             'state' : state, 'cause' : cause, 'cwe' : cwe, \
#             'indicators' : indicators, \
#             'branchId' : branchId, 'revisionId' : revisionId, \
#             'closed_date': str(closed_date), \
#             'age': age, 'ttr': ttr

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0"
}


# First construct rules:
#{
#    "id": "3f292041e51d22005ce48f39df3585d44ce1b0ad",
#    "name": "js/unused-local-variable",
#    "shortDescription": {
#        "text": "Unused variable, import, function or class"
#    },
#    "fullDescription": {
#        "text": "Unused variables, imports, functions or classes may be a symptom of a bug and should be examined carefully."
#    },
#    "defaultConfiguration": {
#        "level": "note"
#    },
#    "properties": {
#        "tags": [
#            "maintainability"
#        ],
#        "precision": "very-high"
#    }
#},

sarif_rules = []
sarif_checkers = dict()
for issue in issues:
    if (issue["checker"] in sarif_checkers): continue

    rule = dict()
    rule['id'] = issue["checker"]
    rule['name'] = issue["checker"]
    rule['shortDescription'] = { "text": issue['name'] }
    rule['fullDescription'] = { "text": issue['description'] + " " + issue['local_effect']}
    rule['properties'] = {
        "tags": [ "security" ],
        "precision": "very-high"
    }
    if (issue['severity'] == "high"):
       rule['defaultConfiguration'] = { "level": "error" }
       rule['properties']['security-severity'] = "8.9"
    elif (issue['severity'] == "moderate"):
        rule['defaultConfiguration'] = { "level": "warning" }
        rule['properties']['security-severity'] = "6.9"
    else:
        rule['defaultConfiguration'] = { "level": "note" }
        rule['properties']['security-severity'] = "3.9"

    sarif_rules.append(rule)
    sarif_checkers[issue["checker"]] = 1

sarif_tool = {
    "driver": {
        "name": "Synopsys Coverity on Polaris",
        "semanticVersion": "1.0.0",
        "rules": sarif_rules,
    }
}


# Now set up results
sarif_results = []
for issue in issues:
    result = dict()
    result['ruleId'] = issue['checker']
    # get the event and
    message = f"{issue['main_event']}"
    if ("remediation" in issue):
        message = message + f"\n\n{issue['remediation']}"
    #result['message'] = { "text": issue['name'] }
    result['message'] = {"text": message}
    if (issue['severity'] == "high"):
       result['level'] = "error"
    elif (issue['severity'] == "moderate"):
        result['level'] = "warning"
    else:
        result['level'] = "note"

    result["locations"] = [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": issue['path']
                    # uriBaseId do not use
                },
                "region": {
                    "startLine": issue['line'],
                    "startColumn": 1,
                    "endLine": issue['line'],
                    "endColumn": 1
                }
            }
        }
    ]

    result['codeFlows'] = [
        {
            "threadFlows": [
                {
                    "locations": []
                }
            ]
        }
    ]

    for threadFlow in issue['codeFlows']:
        result['codeFlows'][0]['threadFlows'][0]['locations'].append(
            {
                "location": {
                    "physicalLocation": {
                        "region": {
                            "startLine": threadFlow["line"],
                            "endLine": threadFlow["line"],
                            "startColumn": 1,
                            "endColumn": 1
                        },
                        "artifactLocation": {
                            "uri": threadFlow["file"]
                        }
                    },
                    "message": {
                        "text": threadFlow["message"]
                    }
                }
            }
        )

    result["partialFingerprints"] = {
        "primaryLocationLineHash": issue["finding-key"]
    }

    sarif_results.append(result)

sarif["runs"] = [
    {
        "tool": sarif_tool,
        "results": sarif_results
    }
]

print("SARIF:")
print(json.dumps(sarif, indent=4))

with open('synopsys-coverity-github-sarif.json', 'w') as fp:
  json.dump(sarif, fp, indent=4)

# Test GitHub APIs

#github_api_url = os.getenv("GITHUB_API_URL")
#github_token = os.getenv("GITHUB_TOKEN")
#github_repo = os.getenv("GITHUB_REPOSITORY")
#github_sha = os.getenv("GITHUB_SHA")
#if (github_api_url == None or github_token == None or github_repo == None or github_sha == None):
#    print(f"ERROR: Must specificy GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_SHA and/or GITHUB_TOKEN environment variables")
#    sys.exit(1)
#
#g = Github(github_token, base_url=github_api_url)
#
#if (debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
#repo = g.get_repo(github_repo)
#if (debug): print(repo)
#
## Set to success and description if all good
#status = repo.get_commit(sha=github_sha).create_status(
#    state="error",
#    target_url=summaryUrl,
#    description="Failed due to new issues",
#    context="Coverity on Polaris"
#)
#print(status)

##check_run = repo.create_check_run(name="Coverity on Polaris", head_sha=github_sha)
##print(check_run)






  #const head_sha = getSha()
#
 # const response = await octokit.rest.checks.create({
# owner: context.repo.owner,
  #  repo: context.repo.repo,
  #  name: CHECK_NAME,
  #  head_sha
  #})