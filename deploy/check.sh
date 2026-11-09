#!/usr/bin/env bash
# Usage: deploy/check.sh
#
# Offline static checks of deploy/terraform, all through Docker (no GCP
# credentials needed): terraform fmt, terraform init -backend=false + validate
# (the module and every environment), tflint (google ruleset), checkov.
# Every step runs; the script exits non-zero if any of them failed.
#
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY (and the lowercase forms) are
# passed into the containers when set. GITHUB_TOKEN, when set, is passed to
# tflint --init to avoid GitHub API rate limits.
# Caches (provider and tflint plugins, Terraform data dirs): deploy/.cache/.
set -euo pipefail

TF_IMAGE="hashicorp/terraform:1.16.7"
TFLINT_IMAGE="ghcr.io/terraform-linters/tflint:v0.65.0"
CHECKOV_IMAGE="bridgecrew/checkov:3.3.30"

if [[ $# -gt 0 ]]; then
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Docker Desktop on Windows needs a Windows path for bind mounts, and Git Bash
# must not rewrite container paths such as /work.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    host_dir="$(cd "$deploy_dir" && pwd -W)"
    export MSYS_NO_PATHCONV=1
    user_args=()
    ;;
  *)
    host_dir="$deploy_dir"
    # Files created in the bind mount (lock file, caches) stay owned by the caller.
    user_args=(--user "$(id -u):$(id -g)" -e HOME=/tmp)
    ;;
esac

mkdir -p \
  "$deploy_dir/.cache/terraform-plugins" \
  "$deploy_dir/.cache/tflint-plugins" \
  "$deploy_dir/.cache/tfdata"

proxy_args=()
for var in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
  if [[ -n "${!var:-}" ]]; then
    proxy_args+=(-e "$var")
  fi
done

docker_run() {
  docker run \
    --rm \
    "${user_args[@]}" \
    "${proxy_args[@]}" \
    -v "$host_dir:/work" \
    "$@"
}

failed=()

step() {
  local name="$1"
  shift
  echo
  echo "==> $name"
  if "$@"; then
    echo "--> $name: ok"
  else
    echo "--> $name: FAILED"
    failed+=("$name")
  fi
}

tf_fmt() {
  docker_run \
    -w /work/terraform \
    "$TF_IMAGE" \
    fmt -check -recursive -diff
}

tf_validate() {
  local dir="$1"
  local data_dir="/work/.cache/tfdata/${dir//\//_}"
  docker_run \
    -w "/work/terraform/$dir" \
    -e TF_IN_AUTOMATION=1 \
    -e TF_DATA_DIR="$data_dir" \
    -e TF_PLUGIN_CACHE_DIR=/work/.cache/terraform-plugins \
    --entrypoint sh \
    "$TF_IMAGE" \
    -c "terraform init -backend=false -input=false -no-color >/dev/null && terraform validate -no-color"
}

tflint_run() {
  local token_args=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    token_args=(-e GITHUB_TOKEN)
  fi
  docker_run \
    "${token_args[@]}" \
    -w /work/terraform \
    -e TFLINT_PLUGIN_DIR=/work/.cache/tflint-plugins \
    --entrypoint sh \
    "$TFLINT_IMAGE" \
    -c "tflint --init --config /work/.tflint.hcl >/dev/null && tflint --recursive --config /work/.tflint.hcl --format compact"
}

checkov_run() {
  docker_run \
    -w /work \
    "$CHECKOV_IMAGE" \
    --config-file /work/.checkov.yaml \
    --directory /work/terraform
}

step "terraform fmt" tf_fmt
step "validate modules/exploit-watch" tf_validate modules/exploit-watch
for env_dir in "$deploy_dir"/terraform/envs/*/; do
  env_name="$(basename "$env_dir")"
  step "validate envs/$env_name" tf_validate "envs/$env_name"
done
step "tflint" tflint_run
step "checkov" checkov_run

echo
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "FAILED: ${failed[*]}"
  exit 1
fi
echo "All checks passed."
