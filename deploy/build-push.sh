#!/usr/bin/env bash
# Usage: deploy/build-push.sh --project <project_id> [--region europe-west4] [--allow-dirty]
#
# Builds the job image from stack/job (stack/job/Dockerfile), tags it with the
# git short sha, pushes it to
#   <region>-docker.pkg.dev/<project>/fairct/exploit-watch
# and prints the digest reference (...@sha256:...) for image_digest in
# terraform.tfvars. Tags are immutable: if the tag is already in the
# registry, nothing is built and the existing digest is printed.
#
#   --allow-dirty  build although stack/job has uncommitted changes; the tag
#                  then gets a -dirty-<UTC time> suffix
#
# Needs: git, docker, gcloud (logged in, allowed to push to the repository).
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY are passed as build args when set.
# Only the digest reference goes to stdout; progress goes to stderr.
set -euo pipefail

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

project=""
region="europe-west4"
allow_dirty=false
repository="fairct"
image_name="exploit-watch"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) project="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --allow-dirty) allow_dirty=true; shift ;;
    -h | --help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$project" ]] || usage
[[ "$region" == europe-* ]] || { echo "--region must be an EU region (europe-*)" >&2; exit 2; }
for tool in git docker gcloud; do
  command -v "$tool" >/dev/null || { echo "$tool not found in PATH" >&2; exit 1; }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

sha="$(git rev-parse --short HEAD)"
tag="$sha"
if [[ -n "$(git status --porcelain -- stack/job)" ]]; then
  if [[ "$allow_dirty" != true ]]; then
    echo "stack/job has uncommitted changes; commit them or pass --allow-dirty" >&2
    exit 1
  fi
  tag="$sha-dirty-$(date -u +%Y%m%dT%H%M%SZ)"
fi

registry="$region-docker.pkg.dev"
image="$registry/$project/$repository/$image_name"

digest_of() {
  gcloud artifacts docker images describe "$1" \
    --project="$project" \
    --format="value(image_summary.digest)" 2>/dev/null
}

if existing="$(digest_of "$image:$tag")" && [[ -n "$existing" ]]; then
  echo "==> $image:$tag already pushed (immutable tags); not rebuilding" >&2
  echo "$image@$existing"
  exit 0
fi

echo "==> Configuring docker credentials for $registry" >&2
gcloud auth configure-docker "$registry" --quiet >&2

build_args=()
for var in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
  if [[ -n "${!var:-}" ]]; then
    build_args+=(--build-arg "$var")
  fi
done

echo "==> Building $image:$tag" >&2
# A single-platform image manifest (no provenance index) is what Cloud Run and
# Artifact Analysis scan and run.
docker build \
  --platform linux/amd64 \
  --provenance=false \
  "${build_args[@]}" \
  --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
  --label "org.opencontainers.image.source=cyber-dashboard-poc" \
  --file stack/job/Dockerfile \
  --tag "$image:$tag" \
  stack/job >&2

echo "==> Pushing $image:$tag" >&2
docker push "$image:$tag" >&2

digest="$(digest_of "$image:$tag")"
[[ -n "$digest" ]] || { echo "could not read the digest of $image:$tag" >&2; exit 1; }

cat >&2 <<EOF
==> Pushed. Vulnerability scan (Artifact Analysis), once it has run:
  gcloud artifacts docker images describe $image@$digest --show-package-vulnerability
==> Set in terraform.tfvars:
  image_digest = "$image@$digest"
EOF
echo "$image@$digest"
