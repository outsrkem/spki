#!/bin/bash
workspace=$(cd `dirname $0`/..; pwd)
cd "${workspace}" || { echo "enter workspace failed: ${workspace}"; exit 1; }

app=spki
version="build_0"

if tag=$(git describe --exact-match --tags HEAD 2>/dev/null); then
    version="${tag##v}"
fi

if [ -n "$1" ]; then
    version="$1"
fi

if ! commit=`git rev-parse HEAD`; then
    echo "ERROR: failed to get git commit, check git repository"
    exit 1
fi

if [ -z "${DOCKER_REPOSITORY}" ]; then
    DOCKER_REPOSITORY=local
fi

repository="${DOCKER_REPOSITORY}"

docker build \
    --build-arg SPKI_VERSION=${version} \
    --build-arg SPKI_REVISION=${commit} \
    --label org.opencontainers.image.revision=${commit} \
    --label org.opencontainers.image.version=${version} \
    --tag ${repository}/${app}:${version} .

if [ -n "${DOCKER_REPOSITORY}" -a "${DOCKER_REPOSITORY}" != "local" ]; then
    docker push ${repository}/${app}:${version}
fi
