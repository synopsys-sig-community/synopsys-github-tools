#!/usr/bin/python

import json
import sys
import os
import argparse
import urllib
import glob

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Post Coverity issue summary to GitHub SARIF')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--coverity-json', required=True, help='Coverity JSON output')
parser.add_argument('--polaris', default=False, action='store_true', help='Using Coverity on Polaris')

args = parser.parse_args()

debug = int(args.debug)
coverity_json = args.coverity_json
polaris = args.polaris

# Process output from Polaris CLI
with open(coverity_json) as f:
  data = json.load(f)

print(f"INFO: Reading incremental analysis results from {coverity_json}")
if(debug): print("DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n")

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
for issue in data["issues"]:
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

print("SARIF:")
print(json.dumps(sarif, indent=4))

with open('synopsys-coverity-github-sarif.json', 'w') as fp:
  json.dump(sarif, fp, indent=4)
