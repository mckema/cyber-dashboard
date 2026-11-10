#!/usr/bin/env bash
# Usage: infra/gcp/bootstrap.sh --project <project_id> [--env sandbox|prod] [--region europe-west4] [--bucket <name>] [--cmek]
#
# Once per GCP project, before the first terraform init: enables the APIs
# Terraform itself needs (Service Usage, Cloud Resource Manager, Cloud Storage)
# and creates the Terraform state bucket (versioning, uniform bucket-level
# access, public access prevention, noncurrent versions pruned). Prints the
# bucket name. Safe to run again: existing settings are re-applied.
#
#   --bucket  default exploit-watch-tfstate-<env> (bucket names are global;
#             pass another name if that one is taken, then use it in
#             terraform init -backend-config="bucket=<name>")
#   --cmek    also create the Secret Manager service agent, needed before the
#             first apply with enable_cmek = true
#
# Needs: gcloud, logged in as a user allowed to enable services and create
# buckets in the project (gcloud auth login).
set -euo pipefail

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

project=""
env_name="sandbox"
region="europe-west4"
bucket=""
cmek=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) project="${2:-}"; shift 2 ;;
    --env) env_name="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --bucket) bucket="${2:-}"; shift 2 ;;
    --cmek) cmek=true; shift ;;
    -h | --help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$project" ]] || usage
[[ "$env_name" == "sandbox" || "$env_name" == "prod" ]] || { echo "--env must be sandbox or prod" >&2; exit 2; }
[[ "$region" == europe-* ]] || { echo "--region must be an EU region (europe-*)" >&2; exit 2; }
bucket="${bucket:-exploit-watch-tfstate-$env_name}"

command -v gcloud >/dev/null || { echo "gcloud not found in PATH" >&2; exit 1; }

echo "Project: $project  env: $env_name  region: $region  bucket: gs://$bucket" >&2

echo "==> Enabling APIs needed by Terraform" >&2
gcloud services enable \
  serviceusage.googleapis.com \
  cloudresourcemanager.googleapis.com \
  storage.googleapis.com \
  --project="$project"

if gcloud storage buckets describe "gs://$bucket" \
  --project="$project" \
  --format="value(name)" >/dev/null 2>&1; then
  echo "==> Bucket gs://$bucket exists; re-applying settings" >&2
else
  echo "==> Creating bucket gs://$bucket" >&2
  gcloud storage buckets create "gs://$bucket" \
    --project="$project" \
    --location="$region" \
    --default-storage-class=STANDARD \
    --uniform-bucket-level-access \
    --public-access-prevention
fi

# Keep at most 10 noncurrent versions of each state file, none older than 90 days.
lifecycle_file="$(mktemp)"
trap 'rm -f "$lifecycle_file"' EXIT
cat >"$lifecycle_file" <<'JSON'
{
  "rule": [
    {"action": {"type": "Delete"}, "condition": {"isLive": false, "numNewerVersions": 10}},
    {"action": {"type": "Delete"}, "condition": {"daysSinceNoncurrentTime": 90}}
  ]
}
JSON
# gcloud on Windows is a native program: give it a Windows path.
if command -v cygpath >/dev/null; then
  lifecycle_arg="$(cygpath -w "$lifecycle_file")"
else
  lifecycle_arg="$lifecycle_file"
fi

gcloud storage buckets update "gs://$bucket" \
  --project="$project" \
  --versioning \
  --uniform-bucket-level-access \
  --public-access-prevention \
  --lifecycle-file="$lifecycle_arg" \
  --update-labels="app=exploit-watch,env=$env_name,managed-by=bootstrap"

if [[ "$cmek" == true ]]; then
  echo "==> Creating the Secret Manager service agent (CMEK)" >&2
  gcloud services enable \
    secretmanager.googleapis.com \
    cloudkms.googleapis.com \
    --project="$project"
  gcloud beta services identity create \
    --service=secretmanager.googleapis.com \
    --project="$project"
fi

cat >&2 <<EOF
==> Done. Next:
  gcloud auth application-default login
  cd infra/gcp/terraform/envs/$env_name
  terraform init -backend-config="bucket=$bucket"
EOF
echo "$bucket"
