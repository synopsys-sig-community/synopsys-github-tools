#!/bin/sh -x
docker build -t jcroall/gh-runner .
#docker run --name=gh-runner --rm --env-file=env.sh jcroall/gh-runner
docker run \
  --env-file=env.sh \
  --name runner \
  jcroall/gh-runner
