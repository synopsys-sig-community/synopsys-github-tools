#!/usr/bin/python

import json
import sys
import os
import argparse
import re
import urllib
import glob

# Parse command line arguments
from github import Github

truncate_security_results = True

def is_security_result(events):
    for event in events:
        if ("taint" in event['tag']):
            return True
        elif ("sink" in event['tag']):
            return True

    return False

def event_format_markdown(number, tag, description):
    # "Event #{comment_event['number']} {comment_event['tag']}: {comment_event['description']}\n"
    if (tag == "remediation"):
        output = f":brain: **Event #{number} {tag}: {description}**\n"
    elif (tag == "sink"):
        output = f":warning: **Event #{number} {tag}: {description}**\n"
    else:
        output = f":wavy_dash: Event #{number} {tag}: {description}\n"

    return output

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Post Coverity issue summary to GitHub SARIF')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--coverity-json', required=True, help='Coverity JSON output')
parser.add_argument('--polaris', default=False, action='store_true', help='Using Coverity on Polaris')
parser.add_argument('--comment-on-github-pr', default=False, action='store_true', help='Comment on GitHub PR')

args = parser.parse_args()

debug = int(args.debug)
coverity_json = args.coverity_json
polaris = args.polaris
comment_on_github_pr = args.comment_on_github_pr

if (comment_on_github_pr):
    github_api_url = os.getenv("GITHUB_API_URL")
    github_token = os.getenv("GITHUB_TOKEN")
    github_repository = os.getenv("GITHUB_REPOSITORY")
    github_sha = os.getenv("GITHUB_SHA")
    github_head_ref = os.getenv("GITHUB_HEAD_REF")
    github_base_ref = os.getenv("GITHUB_BASE_REF")

    print(f"github_repository={github_repository}")
    print(f"github_sha={github_sha}")
    print(f"github_head_ref={github_head_ref}")
    print(f"github_base_ref={github_base_ref}")

    if (github_api_url == None or github_token == None or github_repository == None or github_head_ref == None or github_base_ref == None or github_sha == None):
        print(f"ERROR: Must specificy GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_HEAD_REF, GITHUB_BASE_REF and/or GITHUB_TOKEN environment variables")
        sys.exit(1)

    github = Github(github_token, base_url=github_api_url)

    if (debug): print(f"DEBUG: Look up GitHub repo '{github_repository}'")
    github_repo = github.get_repo(github_repository)
    if (debug): print(github_repo)

    if (debug): print(f"DEBUG: Look up GitHub ref '{github_head_ref}'")
    # Note to subtract the first 5 characters, "refs/" becuase the SDK will prepend that
    #ref = github_repo.get_git_ref(github_head_ref[5:])
    ref = github_repo.get_git_ref(github_head_ref)
    if (debug): print(ref)

    github_sha = ref.object.sha
    if (debug): print(f"DEBUG: Look for SHA {github_sha}")

    print(f"DEBUG: Found Git sha {github_sha} for ref '{github_head_ref}'")

    # TODO Should this handle other bases than master?
    pulls = github_repo.get_pulls(state='open', sort='created', base=github_base_ref, direction="desc")
    pr = None
    pr_commit = None
    if (debug): print(f"DEBUG: Pull requests:")
    pull_number_for_sha = 0
    for pull in pulls:
        if (debug): print(f"DEBUG: Pull request number: {pull.number}")
        # Can we find the current commit sha?
        commits = pull.get_commits()
        for commit in commits.reversed:
            if (debug): print(f"DEBUG:   Commit sha: " + str(commit.sha))
            if (commit.sha == github_sha):
                if (debug): print(f"DEBUG:     Found")
                pull_number_for_sha = pull.number
                pr = pull
                pr_commit = commit
                break
        if (pull_number_for_sha != 0): break

    if (pull_number_for_sha == 0):
        print(f"ERROR: Unable to find pull request for commit '{github_sha}'")
        sys.exit(1)

    if (debug): print(f"DEBUG: Found pull request #{pull_number_for_sha}")

    comments = pr.get_issue_comments()
    if (debug):
        print(f"DEBUG: PR Comments: ")
        print(comments)

    coverity_issue_to_comment = {}
    for comment in comments:
        if (debug): print(f"DEBUG:  body={comment.body}")
        m = re.search('## Coverity Issue (.+?):', comment.body)
        if m:
            coverity_issue_to_comment[m.group(1)] = comment

    if (debug): print(f"DEBUG: Found Coverity comments: {coverity_issue_to_comment}")

# Track what are the newly found issues from Polaris
polaris_merge_keys = {}
if (polaris):
    path, filename = os.path.split(coverity_json)
    filename = os.path.splitext(filename)[0]
    newfilename = 'new-issues.json'
    new_issues_json = os.path.join(path, newfilename)

    with open(new_issues_json) as f:
        data = json.load(f)

    for new_issue in data:
        polaris_merge_keys[new_issue['mergeKey']] = True

    print(polaris_merge_keys)

# Process output from Coverity
with open(coverity_json) as f:
  data = json.load(f)

print(f"INFO: Reading incremental analysis results from {coverity_json}")
if(debug): print("DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n")

markdown_comments = dict()

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0"
}

sarif_rules = []
sarif_checkers = dict()
for issue in data["issues"]:
    if (issue["checkerName"] in sarif_checkers): continue

    rule = dict()
    rule['id'] = issue["checkerName"]
    rule['name'] = issue["checkerName"]
    rule['shortDescription'] = { "text": issue["checkerProperties"]["subcategoryShortDescription"] }
    rule['fullDescription'] = { "text": issue["checkerProperties"]['subcategoryLongDescription'] + " " +
                                        issue["checkerProperties"]['subcategoryLocalEffect']}
    rule['properties'] = {
        "tags": [ "security" ],
        "precision": "very-high"
    }
    if (issue["checkerProperties"]['impact'] == "High"):
       rule['defaultConfiguration'] = { "level": "error" }
       rule['properties']['security-severity'] = "8.9"
    elif (issue["checkerProperties"]['impact'] == "Medium"):
        rule['defaultConfiguration'] = { "level": "warning" }
        rule['properties']['security-severity'] = "6.9"
    else:
        rule['defaultConfiguration'] = { "level": "note" }
        rule['properties']['security-severity'] = "3.9"

    sarif_rules.append(rule)
    sarif_checkers[issue["checkerName"]] = 1

sarif_tool = {
    "driver": {
        "name": "Synopsys Coverity on Polaris",
        "semanticVersion": "1.0.0",
        "rules": sarif_rules,
    }
}

# Now set up results
sarif_results = []
seen_merge_keys = {}
for issue in data["issues"]:
    if (issue['mergeKey'] in seen_merge_keys):
        continue

    seen_merge_keys[issue['mergeKey']] = True

    result = dict()
    result['ruleId'] = issue["checkerName"]

    main_event_description = ""
    remediation_event_description = None

    result['codeFlows'] = [
        {
            "threadFlows": [
                {
                    "locations": []
                }
            ]
        }
    ]

    indent = 0

    markdown_comment = f"## Coverity Issue {issue['mergeKey']}: {issue['checkerName']} in {issue['functionDisplayName']} file {issue['strippedMainEventFilePathname']}:{issue['mainEventLineNumber']}\n"
    markdown_comment += f"{issue['checkerProperties']['subcategoryLongDescription']} {issue['checkerProperties']['subcategoryLocalEffect']}\n\n"

    comment_events = []
    previous_file_and_line = ""

    for event in issue["events"]:
        if event["main"] == True:
            main_event_description = event["eventDescription"]
        if event["remediation"] == True:
            remediation_event_description = event["eventDescription"]

        result['codeFlows'][0]['threadFlows'][0]['locations'].append(
            {
                "location": {
                    "physicalLocation": {
                        "region": {
                            "startLine": event["lineNumber"],
                            "endLine": event["lineNumber"],
                            "startColumn": 1,
                            "endColumn": 1
                        },
                        "artifactLocation": {
                            "uri": event["strippedFilePathname"]
                        }
                    },
                    "message": {
                        "text": f"Event #{event['eventNumber']} {event['eventTag']}: {event['eventDescription']}"
                    }
                }
            }
        )

        # Gather events so we can group them in the comment
        comment_event = {
            "filename": event['filePathname'],
            "line": event["lineNumber"],
            "description": event["eventDescription"],
            "tag": event["eventTag"],
            "number": event["eventNumber"]
        }
        if (previous_file_and_line == f"{event['filePathname']}:{event['lineNumber']}"):
            comment_event['has_source'] = False
        else:
            comment_event['has_source'] = True

        previous_file_and_line = f"{event['filePathname']}:{event['lineNumber']}"

        comment_events.append(comment_event)

    is_security = is_security_result(comment_events)

    # Loop through comment events and built pretty code presentation
    i = 0
    while i < len(comment_events):
        comment_event = comment_events[i]

        if (truncate_security_results and is_security):
            if ("taint" in comment_event['tag'] or "sink" in comment_event['tag'] or "remediation" in comment_event['tag']):
                markdown_comment += event_format_markdown(comment_event['number'], comment_event['tag'], comment_event['description'])
        else:
            markdown_comment += event_format_markdown(comment_event['number'], comment_event['tag'], comment_event['description'])
        #markdown_comment += f"Event #{comment_event['number']} {comment_event['tag']}: {comment_event['description']}\n"
        j = i + 1
        comment_event2 = comment_events[j]
        while j < len(comment_events) and comment_event2['has_source'] == False:
            comment_event2 = comment_events[j]
            if (truncate_security_results and is_security):
                if ("taint" in comment_event2['tag'] or "sink" in comment_event2['tag'] or "remediation" in comment_event2['tag']):
                    markdown_comment += event_format_markdown(comment_event2['number'], comment_event2['tag'], comment_event2['description'])
            else:
                markdown_comment += event_format_markdown(comment_event2['number'], comment_event2['tag'], comment_event2['description'])
            #markdown_comment += f"Event #{comment_event2['number']} {comment_event2['tag']}: {comment_event2['description']}\n"
            j += 1

        source_code = open(comment_event['filename'])
        source_content = source_code.readlines()

        markdown_comment += f"From {comment_event['filename']}:{comment_event['line']}:\n"
        markdown_comment += "```\n"
        begin_line = comment_event["line"] - 3
        if (begin_line < 0): begin_line = 0
        end_line = comment_event["line"] + 2
        if (end_line > len(source_content)): end_line = len(source_content)
        line = begin_line +1
        for source_line in source_content[begin_line:end_line]:
            if (line == comment_event["line"]):
                markdown_comment += f" {line:5d} {source_line}"
            else:
                markdown_comment += f" {line:5d} {source_line}"
            line += 1
        markdown_comment += "```\n\n"

        i = j

    if (comment_on_github_pr):
        if (issue["mergeKey"] in coverity_issue_to_comment):
            if (debug): print(f"DEBUG: Coverity issue {issue['mergeKey']} already has comment={coverity_issue_to_comment[issue['mergeKey']]}")
            comment.edit(markdown_comment)
        else:
            if (debug): print(f"DEBUG: Coverity issue {issue['mergeKey']} does not have commment")
            pr.create_issue_comment(body=markdown_comment)

        if (debug): print(f"DEBUG: New comment: {markdown_comment}")

    # get the event and
    message = main_event_description
    if (remediation_event_description != None):
        message = message + f"\n\n{remediation_event_description}"
    result['message'] = {"text": message}
    if (issue["checkerProperties"]['impact'] == "High"):
       result['level'] = "error"
    elif (issue["checkerProperties"]['impact'] == "Medium"):
        result['level'] = "warning"
    else:
        result['level'] = "note"

    # Comment on GitHub PR


    result["locations"] = [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": issue['strippedMainEventFilePathname']
                    # uriBaseId do not use
                },
                "region": {
                    "startLine": issue['mainEventLineNumber'],
                    "startColumn": 1,
                    "endLine": issue['mainEventLineNumber'],
                    "endColumn": 1
                }
            }
        }
    ]

    result["partialFingerprints"] = {
        "primaryLocationLineHash": issue["mergeKey"]
    }

    sarif_results.append(result)

sarif["runs"] = [
    {
        "tool": sarif_tool,
        "results": sarif_results
    }
]

with open('synopsys-coverity-github-sarif.json', 'w') as fp:
  json.dump(sarif, fp, indent=4)
