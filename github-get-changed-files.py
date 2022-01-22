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

truncate_security_results = True

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Get changed files for a GitHub Push or Pull Requesyt')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--output', default="github-changed-files.txt", help="Output file")

args = parser.parse_args()

debug = int(args.debug)
output = args.output

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
# Actually look up the head not merge ref to get the latest commit so
# we can find the pull request
ref = github_repo.get_git_ref(github_ref[5:].replace("/merge", "/head"))
if debug: print(f"DEBUG: GitHub ref={ref}")

pull_number_for_sha = None
m = re.search('pull\/(.+?)\/', github_ref)
if m:
    pull_number_for_sha = int(m.group(1))

if debug: print(f"DEBUG: Pull request #{pull_number_for_sha}")

base = None
head = None

if pull_number_for_sha == None:
    # Push - just list files changed in this commit
    print(f"INFO: Operating on a push")

    head = github_repo.get_commit(sha=github_sha)
    with open(output, "w") as fp:
        for file in head.files:
            if debug: print(f"DEBUG: File in commit: {file.filename}")
            fp.write(f"{file.filename}\n")
    fp.close()

else:
    # Pull Request
    print(f"INFO: Operating on a pull request")

    pr = github_repo.get_pull(pull_number_for_sha)
    pull_number_for_sha = pr.number

    files = pr.get_files()
    with open(output, "w") as fp:
        for file in files:
            if debug: print(f"DEBUG: File in pull request: {file.filename}")
            fp.write(f"{file.filename}\n")

