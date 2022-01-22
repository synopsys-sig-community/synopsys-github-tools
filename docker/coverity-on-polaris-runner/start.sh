#!/bin/bash

if [ -n "${GITHUB_REPOSITORY}" ]
then
  auth_url="https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPOSITORY}/actions/runners/registration-token"
  registration_url="https://github.com/${GITHUB_OWNER}/${GITHUB_REPOSITORY}"
else
  auth_url="https://api.github.com/orgs/${GITHUB_OWNER}/actions/runners/registration-token"
  registration_url="https://github.com/${GITHUB_OWNER}"
fi

generate_token() {
  payload=$(curl -sX POST -H "Authorization: token ${GITHUB_PERSONAL_TOKEN}" "${auth_url}")
  runner_token=$(echo "${payload}" | jq .token --raw-output)

  if [ "${runner_token}" == "null" ]
  then
    echo "${payload}"
    exit 1
  fi

  echo "${runner_token}"
}

cleanup() {
  ./config.sh remove --unattended --token "$(generate_token)"
}

runner_id=${RUNNER_NAME}_$(openssl rand -hex 6)
echo "Registering runner ${runner_id}"

./config.sh \
  --name "${runner_id}" \
  --labels "${RUNNER_LABELS}" \
  --token "$(generate_token)" \
  --url "${registration_url}" \
  --unattended \
  --replace \
  --ephemeral

cleanup() {
    echo "Removing runner..."
    ./config.sh remove --unattended --token "$(generate_token)"
}

trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

./run.sh & wait $!
