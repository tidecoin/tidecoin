#!/usr/bin/env bash
# Copyright (c) 2026 The Tidecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# Keep runtime resources private to this invocation. CONTAINER_NAME remains
# stable because it also identifies the persistent ccache/depends volumes.
init_ci_docker() {
  if [ -z "${CI_DOCKER_NAME:-}" ]; then
    local suffix
    suffix=$(python3 -c 'import uuid; print(uuid.uuid4().hex)') || return
    CI_DOCKER_NAME="tidecoin-ci-${CONTAINER_NAME}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${suffix}"
    CI_DOCKER_NAME=$(printf '%s' "$CI_DOCKER_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.-' '-')
  fi
  export CI_DOCKER_NAME
  export CI_DOCKER_IMAGE="${CI_DOCKER_NAME}:latest"
}

# Idempotent and best-effort: preserve the test's exit status, but report cleanup
# failures. Never prune shared images, delete by image ID, or remove cache volumes.
cleanup_ci_docker() {
  if [ -z "${CI_DOCKER_NAME:-}" ] || [ -z "${CI_DOCKER_IMAGE:-}" ]; then
    return
  fi
  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    echo "Warning: Docker unavailable; could not clean up $CI_DOCKER_NAME" >&2
    return
  fi
  local container
  for container in "${CI_DOCKER_NAME}-bind-check" "$CI_DOCKER_NAME"; do
    if docker container inspect "$container" >/dev/null 2>&1; then
      if ! docker container rm --force "$container"; then
        echo "Warning: could not remove CI container $container" >&2
      fi
    fi
  done
  if docker image inspect "$CI_DOCKER_IMAGE" >/dev/null 2>&1; then
    if ! docker image rm --no-prune "$CI_DOCKER_IMAGE"; then
      echo "Warning: could not remove CI image tag $CI_DOCKER_IMAGE" >&2
    fi
  fi
}
