#!/bin/bash
set -e

IMAGE=registry.lestak.sh/402
TAG=$GIT_COMMIT

docker build -f Dockerfile \
    --build-arg GITHUB_TOKEN=$GITHUB_TOKEN \
    -t $IMAGE:$TAG \
    .

docker push $IMAGE:$TAG

sed "s,$IMAGE:.*,$IMAGE:$TAG,g" devops/k8s/*.yaml | kubectl apply -f -
