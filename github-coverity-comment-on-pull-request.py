#!/usr/bin/python

import json
import subprocess
import sys
import os
import argparse
import ssl
import re
import linecache
import urllib
import glob
import traceback

# Parse command line arguments
from os.path import exists
from pprint import pprint

import requests
from github import Github

from urllib.parse import urlparse
from wscoverity import WebServiceClient, ConfigServiceClient, DefectServiceClient

def find_ref_for_line(filepath, line):
    line_range = str(line) + ',' + str(line)

    if (not exists(filepath)):
        print(f"WARNING: File '{filepath}' does not exist")
        return None

    try:
        output = subprocess.check_output(['git', 'blame', '-l', '-L', line_range, filepath])
    except subprocess.CalledProcessError as grepexc:
        print(f"WARNING: Git blame failed: {grepexc}")
        return None, None

    for line in output.splitlines():
        # 9419f31f2c6878e8b29370a73b1d96bd3f69d6f2 (James Croall 2022-01-09 14:26:41 +0000 21) var req = https.request({port: 1336, host: 'https://example2.com', rejectUnauthorized: false}, function(){
        line = line.decode("utf-8")
        sline = line.split(' ')
        return sline[0]

    return None


def get_lines_from_file(filename, start_line, end_line):
    ret_lines = dict()

    with open(filename, 'r') as fp:
        # lines to read
        line_numbers = range(start_line, end_line)
        # To store lines
        lines = []
        for i, line in enumerate(fp):
            # read line 4 and 7
            if i in line_numbers:
                ret_lines[i] = line.strip()
            elif i > end_line:
                # don't read after line 7 to save time
                break

    return ret_lines


truncate_security_results = True

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Post Coverity issue summary to GitHub SARIF')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--coverity-json', required=True, help='Coverity JSON output')
parser.add_argument('--sigma-json', required=True, help='Sigma JSON output')
parser.add_argument('--url', required=True, help='Coverity Connect URL')
parser.add_argument('--stream', required=True, help='Coverity stream name for reference')

args = parser.parse_args()

debug = int(args.debug)
coverity_json = args.coverity_json
sigma_json = args.sigma_json
url = args.url
stream = args.stream

coverity_username = os.getenv("COV_USER")
coverity_passphrase = os.getenv("COVERITY_PASSPHRASE")

if (coverity_username == None or coverity_passphrase == None):
    print(f"ERROR: Must specificy COV_USER and COVERITY_PASSPHRASE environment variables")
    sys.exit(1)

o = urlparse(args.url)
host = o.hostname
port = str(o.port)
scheme = o.scheme
if scheme == "https":
    do_ssl = True
    port = "443"
else:
    do_ssl = False

# TODO Properly handle self-signed certificates, but this is challenging in Python
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

print(f"DEBUG: Connect to host={host} port={port}")
defectServiceClient = DefectServiceClient(host, port, do_ssl, coverity_username, coverity_passphrase)

mergedDefectDOs = defectServiceClient.get_merged_defects_for_stream(stream)

# Look for merge keys seen in reference stream - but ignore if they are "Fixed" since we will want to include
# them if they are re-introduced
merge_keys_seen_in_ref = dict()
for md in mergedDefectDOs:
    for dsa in md.defectStateAttributeValues:
        adId = dsa.attributeDefinitionId
        if (adId.name == "DefectStatus"):
            advId = dsa.attributeValueId
            if (advId.name != "Fixed"):
                merge_keys_seen_in_ref[md.mergeKey] = 1

if debug: print(f"DEBUG: merge_keys_seen_in_ref={merge_keys_seen_in_ref}")

total_issues_commented = 0

# Process output from Coverity
with open(coverity_json, encoding='utf-8') as f:
  data = json.load(f)

print(f"INFO: Reading incremental analysis results from {coverity_json}")
if(debug): print("DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n")

local_issues = data['issues']
issues_to_report = dict()
issues_to_comment_on = []
for issue in local_issues:
    if issue['mergeKey'] in merge_keys_seen_in_ref:
        if debug: print(f"DEBUG: merge key {issue['mergeKey']} seen in reference stream, file={issue['strippedMainEventFilePathname']}")
    else:
        if debug: print(f"DEBUG: merge key {issue['mergeKey']} NOT seen in reference stream, file={issue['strippedMainEventFilePathname']}")
        issues_to_report[issue['mergeKey']] = issue
        issues_to_comment_on.append(issue)

if debug: print(f"DEBUG: Issues to report: {issues_to_report}")

github_api_url = os.getenv("GITHUB_API_URL")
github_token = os.getenv("GITHUB_TOKEN")
github_repository = os.getenv("GITHUB_REPOSITORY")
github_sha = os.getenv("GITHUB_SHA")
github_ref = os.getenv("GITHUB_REF")

if (github_api_url == None or github_token == None or github_repository == None or github_sha == None or github_ref == None):
    print(f"ERROR: Must specificy GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_SHA, GTIHUB_REF and/or GITHUB_TOKEN environment variables")
    sys.exit(1)

if debug:
    print(f"DEBUG: github_repository={github_repository}")
    print(f"DEBUG: github_sha={github_sha}")

github = Github(github_token, base_url=github_api_url)

if (debug): print(f"DEBUG: Look up GitHub repo '{github_repository}'")
github_repo = github.get_repo(github_repository)
if (debug): print(github_repo)

# Remove leading refs/ as the API will prepend it on it's own
# Actually look pu the head not merge ref to get the latest commit so
# we can find the pull request
ref = github_repo.get_git_ref(github_ref[5:].replace("/merge", "/head"))
if debug: print(f"DEBUG: ref={ref}")

pull_number_for_sha = None
m = re.search('pull\/(.+?)\/', github_ref)
if m:
    pull_number_for_sha = int(m.group(1))

if debug: print(f"DEBUG: Pull request #{pull_number_for_sha}")

if pull_number_for_sha == None:
    print(f"ERROR: Unable to find pull request #{pull_number_for_sha}, must be operating on a full analysis")
    sys.exit(1)

pr = github_repo.get_pull(pull_number_for_sha)
pull_number_for_sha = pr.number

if (pull_number_for_sha == 0):
    print(f"ERROR: Unable to find pull request for commit '{github_sha}'")
    sys.exit(1)

if (debug): print(f"DEBUG: Found pull request #{pull_number_for_sha}")

commits = pr.get_commits()

file_changes = dict()
for commit in commits:
    print(commit.raw_data)
    files = commit.files
    for file in files:
        filename = file.filename
        patch = file.patch
        print(f"DEBUG: file={filename} patch={patch}")
        m = re.search('@@ .(\d+,\d+) .(\d+,\d+) @@', patch)
        if m:
            patch_changes = m.group(2)
            (start_line, num_lines) = patch_changes.split(',')
            end_line = int(start_line) + int(num_lines)
            if debug: print(f"DEBUG: Change start_line={start_line} num_lines={num_lines} end_line={end_line}")
            if filename not in file_changes:
                file_changes[filename] = []
            file_changes[filename].append({'start_line': start_line, 'end_line': end_line})

if debug: print(f"DEBUG: File changes={file_changes}")

for issue in issues_to_comment_on:
    if debug: print(f"DEBUG: Comment on issue {issue}")
    filename = issue['strippedMainEventFilePathname']

    if issue['checkerName'].startswith("SIGMA"):
        if debug: print(f"DEBUG: Checker name '{issue['checkerName']}' begins with SIGMA, skipping")
        continue

    if debug: print(f"DEBUG: Issue appears in {filename}")
    if filename not in file_changes:
        if debug: print(f"DEBUG: File '{filename}' not in change set, ignoring")
        continue

    if debug: print(f"DEBUG: File '{filename}' found in change set")

    start_line = issue['mainEventLineNumber']

    events = issue['events']
    remediation = None
    main_desc = None
    for event in events:
        print(f"DEBUG: event={event}")
        if event['remediation'] == True:
            remediation = event['eventDescription']
        if event['main'] == True:
            main_desc = event['eventDescription']

    checkerProps = issue['checkerProperties']
    comment_body = f"**Coverity found issue: {checkerProps['subcategoryShortDescription']} - CWE-{checkerProps['cweCategory']}, {checkerProps['impact']} Severity**\n\n"
    # BAD_CERT_VERIFICATION: The "checkServerIdentity" property in the "tls.connect()" function uses bad cert verification.
    #comment_body += f"**{checkerProps['subcategoryLocalEffect']}**\n\n"

    if (main_desc):
        comment_body += f"**{issue['checkerName']}**: {main_desc} {checkerProps['subcategoryLocalEffect']}\n\n"
    else:
        comment_body += f"**{issue['checkerName']}**: {checkerProps['subcategoryLocalEffect']}\n\n"

    if remediation:
        comment_body += f"**How to fix:** {remediation}\n"

    comment_body += "<details>\n<summary>Click to expand data flow...</summary>\n\n"

    # Build map of lines
    event_tree_lines = dict()
    event_tree_events = dict()
    for event in events:
        event_file = event['strippedFilePathname']
        event_line = int(event['lineNumber'])

        if event_file not in event_tree_lines:
            event_tree_lines[event_file] = dict()
            event_tree_events[event_file] = dict()

        event_line_start = event_line - 3
        if (event_line_start < 0): event_line_start = 0
        event_line_end = event_line + 3
        for i in range(event_line_start, event_line_end):
            event_tree_lines[event_file][i] = 1

        if event_line not in event_tree_events[event_file]:
            event_tree_events[event_file][event_line] = []

        event_tree_events[event_file][event_line].append(f"{event['eventNumber']}. {event['eventTag']}: {event['eventDescription']}")

    if debug: print(f"DEBUG: event_tree_lines={event_tree_lines}")
    if debug: print(f"DEBUG: event_tree_events={event_tree_events}")

    for filename in event_tree_lines.keys():
        comment_body += f"**From {filename}:**\n"

        comment_body += "```\n"
        for i in event_tree_lines[filename].keys():
            if (i in event_tree_events[filename]):
                for event_str in event_tree_events[filename][i]:
                    comment_body += f"{event_str}\n"

            code_line = linecache.getline(filename, i)
            comment_body += f"%5d {code_line}" % i

        comment_body += "```\n"


        #comment_body
        #comment_body += f"{event['eventNumber']}. {event['eventTag']}: {event['eventDescription']}<p>\n"
        #line_begin = start_line - 3
        #if (line_begin < 0): line_begin = 0
        #line_end = start_line + 3
        #lines = get_lines_from_file(last_file, line_begin, line_end)
        #comment_body += f"LINES by {line_begin} to {line_end}: {lines}"

    comment_body += "</details>"

    # Tag with merge key
    comment_body += f"<!-- Coverity {issue['mergeKey']} -->"

    if debug: print(f"DEBUG: comment_body={comment_body}")

    blame_ref = find_ref_for_line(filename, start_line).replace('^', '')
    if blame_ref == None:
        print(f"WARNING: Unable to find reference for {filename}:{start_line}, skipping")
        continue

    if debug: print(f"DEBUG: Reference for line={start_line} is: {blame_ref}")

    comment_post_url = github_api_url + f"/repos/{github_repository}/pulls/{pull_number_for_sha}/comments"
    headers = {'Authorization': f'token {github_token}'}
    params = {
        "accept": "application/vnd.github.v3+json",
        "owner": github_repo.owner,
        "repo": github_repo.name,
        "pull_number": pull_number_for_sha
    }
    body = {
        "body": comment_body,
        "commit_id": blame_ref,
        "path": filename,
        "side": "RIGHT",
        "line": start_line
    }
    if debug: print(f"DEBUG: Creating GitHub PR review comment params={params} body={body}")
    if 1:
        r = requests.post(url = comment_post_url, headers = headers, params = params, data = json.dumps(body))
        if (r.status_code > 250):
            if (r.json()['message'] == "Validation Failed"):
                print(f"WARNING: Unable to validate comment on commit XXX, ignoring")
            else:
                print(f"ERROR: Unable to create GitHub PR review comment:")
                print(r.json())
                sys.exit(1)
        total_issues_commented += 1

# Process output from Sigma
with open(sigma_json) as f:
  data = json.load(f)

print(f"INFO: Reading incremental analysis results from {sigma_json}")
if(debug): print("DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n")

for issue in data['issues']['issues']:
    filename = issue['filepath']
    if filename not in file_changes:
        if debug: print(f"DEBUG: File '{filename}' not in change set, ignoring")
        continue

    if debug: print(f"DEBUG: File '{filename}' found in change set")

    cwe = "N/A"
    if "cwe" in issue['taxonomies']:
        cwe = issue['taxonomies']['cwe'][0]

    comment_body = f"**Coverity Rapid Scan found issue: {issue['summary']} - CWE-{cwe}, {issue['severity']['impact']} Severity**\n\n"
    comment_body += f"{issue['desc'].strip()}\n\n"

    comment_body += f"**How to fix:** {issue['remediation'].strip()}\n"

    issue_line = issue['location']['start']['line']
    if "fixes" in issue:
        fix = issue['fixes'][0]
        fix_desc = fix['desc']
        fix_action = fix['actions'][0]
        if debug: print(f"DEBUG: Fix action={fix_action}")

        fix_location_start_line = fix_action['location']['start']['line']
        fix_location_end_col = fix_action['location']['end']['column']
        fix_location_start_col = fix_action['location']['start']['column']
        code_line = linecache.getline(filename, fix_location_start_line)

        if debug: print(f"DEBUG: Original line: {code_line}")

        # suggestion = current_line.substring(0, fix_location_start_col-1) +
        # issue['fixes'][0]['actions'][0]['contents'] + current_line.substring(fix_location_end_col-1, current_line.length)

        suggestion = code_line[0:fix_location_start_col-1] + fix_action['contents'] + code_line[fix_location_end_col-1:len(code_line)]

        if debug: print(f"DEBUG: Sugestion: {suggestion}")

        comment_body += f"```suggestion\n" \
                        f"{suggestion}" \
                        f"```\n"

    if debug: print(f"DEBUG: Comment body={comment_body}")

    blame_ref = find_ref_for_line(filename, start_line).replace('^', '')
    if blame_ref == None:
        print(f"WARNING: Unable to find reference for {filename}:{start_line}, skipping")
        continue

    if debug: print(f"DEBUG: Reference for line={start_line} is: {blame_ref}")

    comment_post_url = github_api_url + f"/repos/{github_repository}/pulls/{pull_number_for_sha}/comments"
    headers = {'Authorization': f'token {github_token}'}
    params = {
        "accept": "application/vnd.github.v3+json",
        "owner": github_repo.owner,
        "repo": github_repo.name,
        "pull_number": pull_number_for_sha
    }
    body = {
        "body": comment_body,
        "commit_id": blame_ref,
        "path": filename,
        "side": "RIGHT",
        "line": issue_line
    }
    if debug: print(f"DEBUG: Creating GitHub PR review comment params={params} body={body}")
    if 1:
        try:
            r = requests.post(url = comment_post_url, headers = headers, params = params, data = json.dumps(body))
            if (r.status_code > 250):
                print(f"ERROR: Unable to create GitHub PR review comment:")
                print(r.json())
                sys.exit(1)
            total_issues_commented += 1
        except:
            print(f"INFO: Validation for comment failed, it must have not been included in commit")



# Replace with policy based scan
if total_issues_commented > 0:
        status = github_repo.get_commit(sha=github_sha).create_status(
            state="failure",
            target_url="https://synopsys.com/software",
            description="Coverity static analysis found vulnerabilities",
            context="Synopsys Coverity"
        )
else:
        status = github_repo.get_commit(sha=github_sha).create_status(
            state="success",
            target_url="https://synopsys.com/software",
            description="Coverity static analysis clear from vulnerabilities",
            context="Synopsys Coverity"
        )



# https://towardsdatascience.com/all-the-things-you-can-do-with-github-api-and-python-f01790fca131
# token = os.getenv('GITHUB_TOKEN', '...')
# owner = "MartinHeinz"
# repo = "python-project-blueprint"
# query_url = f"https://api.github.com/repos/{owner}/{repo}/issues"
# params = {
#     "state": "open",
# }
# headers = {'Authorization': f'token {token}'}
# r = requests.get(query_url, headers=headers, params=params)
# pprint(r.json())

    #pr.create_review_comment(body = comment_body, commit_id = github_sha, path = filename, position = 1, line




        #if m:
        #    pull_number_for_sha = int(m.group(1))

    #files = commit.files
    #for file in files:
    #    filename = file.filename
    #    contents = repo.get_contents(filename, ref=commit.sha).decoded_content



#comments = pr.get_issue_comments()
#if (debug):
#    print(f"DEBUG: PR Comments: ")
#    print(comments)
#
#coverity_issue_to_comment = {}
#for comment in comments:
#    if (debug): print(f"DEBUG:  body={comment.body}")
#    m = re.search('## Coverity Issue (.+?):', comment.body)
#    if m:
#        coverity_issue_to_comment[m.group(1)] = comment
#
#if (debug): print(f"DEBUG: Found Coverity comments: {coverity_issue_to_comment}")


#if (len(polaris_merge_keys.keys()) > 0):
#    print(f"INFO: Found new incremental results, returning exit code 1")
#    sys.exit(1)
