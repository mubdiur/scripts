#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m"

usage() {
  cat <<EOF
Usage: $(basename "$0")

Interactive script to copy contents from a source volume/path to a destination volume/path
using rsync inside a Docker container.

You will be prompted for:
 - Source volume or host path (can be a named Docker volume or a host path)
 - Destination volume or host path
 - Dry-run? (y/N)
 - Mirror (delete extraneous files in destination)? (y/N)

This script mounts the source read-only and runs rsync in a transient container.
EOF
  exit 1
}

# Check docker
if ! command -v docker >/dev/null 2>&1; then
  printf "%s" "${RED}Error:${NC} docker is not installed or not in PATH.\n" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  printf "%s" "${RED}Error:${NC} cannot communicate with the Docker daemon. Ensure you can run 'docker' (maybe you need sudo).\n" >&2
  exit 1
fi

read -rp "Enter source volume or path: " SRC
read -rp "Enter destination volume or path: " DST

if [[ -z "$SRC" || -z "$DST" ]]; then
  printf "%s" "${RED}Error:${NC} Both source and destination are required.\n" >&2
  usage
fi

read -rp "Dry-run only? (y/N): " DRYRUN_ANS
read -rp "Mirror destination (delete files not present in source)? (y/N): " MIRROR_ANS

DRYRUN=false
MIRROR=false

if [[ "${DRYRUN_ANS,,}" == "y" || "${DRYRUN_ANS,,}" == "yes" ]]; then
  DRYRUN=true
fi

if [[ "${MIRROR_ANS,,}" == "y" || "${MIRROR_ANS,,}" == "yes" ]]; then
  MIRROR=true
fi

printf "Preparing to copy from '%s' to '%s'...\n" "$SRC" "$DST"
if $DRYRUN; then
  printf "${YELLOW}Note:${NC} Running in dry-run mode. No files will be modified.\n"
fi
if $MIRROR; then
  printf "${YELLOW}Note:${NC} Mirror mode enabled. Files present in destination but not in source will be deleted.\n"
fi

# Build rsync options
RSYNC_ARGS=("-aH" "--info=progress2" "--progress" "--human-readable" "--stats")
if $MIRROR; then
  RSYNC_ARGS+=("--delete-after" "--delete-excluded")
fi
if $DRYRUN; then
  RSYNC_ARGS+=("--dry-run")
fi

DOCKER_IMAGE=alpine:latest

# Join args for passing into container command
join_args() {
  printf "%s " "$@"
}
RSYNC_CMD=$(join_args "${RSYNC_ARGS[@]}")

# Run the container; mount src read-only
# Use /src/ to copy contents, not the directory itself
docker run --rm -it \
  -v "${SRC}":/src:ro \
  -v "${DST}":/dst \
  "${DOCKER_IMAGE}" sh -c "\
    set -euo pipefail; \
    apk add --no-cache rsync >/dev/null 2>&1 || { printf '%s' \"Failed to install rsync in container\"; exit 2; }; \
    mkdir -p /dst; \
    printf '\033[1;32mRunning rsync inside container\033[0m\n'; \
    rsync ${RSYNC_CMD} /src/ /dst/\"

rc=$?
if [[ $rc -eq 0 ]]; then
  printf "%s" "${GREEN}Rsync completed successfully (exit code 0).${NC}\n"
  if $DRYRUN; then
    printf "%s" "${YELLOW}Dry-run was enabled; no files were changed.${NC}\n"
  fi
  exit 0
else
  printf "%s" "${RED}Rsync failed with exit code %d.${NC}\n" "$rc" >&2
  exit "$rc"
fi
