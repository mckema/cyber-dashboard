#!/usr/bin/env bash
# Usage: infra/gcp/check.sh
#
# Offline static checks, all through Docker (no GCP credentials needed):
# infra/gcp/terraform with terraform fmt, terraform init -backend=false + validate
# (the module and every environment), tflint (google ruleset) and checkov; the
# Rust crate at the repo root with cargo deny (advisories, bans, sources,
# licenses; deny.toml). Every step runs; the script exits non-zero if any failed.
#
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY (and the lowercase forms) are
# passed into the containers when set. GITHUB_TOKEN, when set, is passed to
# tflint --init to avoid GitHub API rate limits.
# Caches: infra/gcp/.cache/ (provider and tflint plugins, Terraform data dirs);
# Docker volumes cargo-deny-bin, cargo-registry and cargo-deny-advisory-db.
# Images are pinned as tag@sha256 (registry index digest); bump the digest
# together with the tag.
set -euo pipefail

TF_IMAGE="hashicorp/terraform:1.16.7@sha256:c9c77f5b9820832cbc7b88d16df406ac6e75fee5a9077e5437db0c54e5ff33e3"
TFLINT_IMAGE="ghcr.io/terraform-linters/tflint:v0.65.0@sha256:2788f4d4fc663c0e953b011b01bf443fe5bfce7587ee916e588e6057b85d6359"
CHECKOV_IMAGE="bridgecrew/checkov:3.3.30@sha256:4b65e89f1fde292249fc0aa0d0db43302c036dfe39f7370b2d3517571082b894"
# Same image as the Dockerfile's build stage.
RUST_IMAGE="rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7"
CARGO_DENY_VERSION="0.20.2"

if [[ $# -gt 0 ]]; then
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$deploy_dir/../.." && pwd)"

# Docker Desktop on Windows needs a Windows path for bind mounts, and Git Bash
# must not rewrite container paths such as /work.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    host_dir="$(cd "$deploy_dir" && pwd -W)"
    host_repo="$(cd "$repo_dir" && pwd -W)"
    export MSYS_NO_PATHCONV=1
    user_args=()
    ;;
  *)
    host_dir="$deploy_dir"
    host_repo="$repo_dir"
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

# docker_run rw|ro <docker run args>: infra/gcp mounted at /work, writable or
# read-only. Read-only steps get a writable mount for their cache only.
docker_run() {
  local mode="$1"
  shift
  docker run \
    --rm \
    "${user_args[@]}" \
    "${proxy_args[@]}" \
    -v "$host_dir:/work:$mode" \
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
  docker_run ro \
    -w /work/terraform \
    "$TF_IMAGE" \
    fmt -check -recursive -diff
}

# Writable: terraform init writes TF_DATA_DIR, the plugin cache and the module's
# lock file (not committed, see .gitignore).
tf_validate() {
  local dir="$1"
  local data_dir="/work/.cache/tfdata/${dir//\//_}"
  docker_run rw \
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
  docker_run ro \
    -v "$host_dir/.cache/tflint-plugins:/work/.cache/tflint-plugins" \
    "${token_args[@]}" \
    -w /work/terraform \
    -e TFLINT_PLUGIN_DIR=/work/.cache/tflint-plugins \
    --entrypoint sh \
    "$TFLINT_IMAGE" \
    -c "tflint --init --config /work/.tflint.hcl >/dev/null && tflint --recursive --config /work/.tflint.hcl --format compact"
}

checkov_run() {
  docker_run ro \
    -w /work \
    "$CHECKOV_IMAGE" \
    --config-file /work/.checkov.yaml \
    --directory /work/terraform
}

# cargo-deny against the repo root (read-only), with deny.toml there. The binary
# is built once into the cargo-deny-bin volume (cargo install --locked) and
# rebuilt when CARGO_DENY_VERSION changes. cargo-deny fetches the RustSec
# advisory database with the git CLI, which the rust image lacks: installed per
# run (apt only honours the lowercase proxy variables). Runs as root: it writes
# only to the named volumes.
cargo_deny_run() {
  docker run \
    --rm \
    "${proxy_args[@]}" \
    -v "$host_repo:/src:ro" \
    -v cargo-deny-bin:/opt/cargo-deny \
    -v cargo-registry:/usr/local/cargo/registry \
    -v cargo-deny-advisory-db:/usr/local/cargo/advisory-dbs \
    -e CARGO_DENY_VERSION="$CARGO_DENY_VERSION" \
    -w /src \
    --entrypoint sh \
    "$RUST_IMAGE" \
    -c '
      set -e
      export http_proxy="${http_proxy:-${HTTP_PROXY:-}}" https_proxy="${https_proxy:-${HTTPS_PROXY:-}}"
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq --no-install-recommends git >/dev/null
      deny=/opt/cargo-deny/bin/cargo-deny
      if [ "$("$deny" --version 2>/dev/null)" != "cargo-deny $CARGO_DENY_VERSION" ]; then
        cargo install --locked --force --quiet \
          --root /opt/cargo-deny \
          --version "$CARGO_DENY_VERSION" \
          cargo-deny
      fi
      "$deny" --locked check advisories bans sources licenses
    '
}

step "terraform fmt" tf_fmt
step "validate modules/exploit-watch" tf_validate modules/exploit-watch
for env_dir in "$deploy_dir"/terraform/envs/*/; do
  env_name="$(basename "$env_dir")"
  step "validate envs/$env_name" tf_validate "envs/$env_name"
done
step "tflint" tflint_run
step "checkov" checkov_run
step "cargo deny" cargo_deny_run

echo
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "FAILED: ${failed[*]}"
  exit 1
fi
echo "All checks passed."
