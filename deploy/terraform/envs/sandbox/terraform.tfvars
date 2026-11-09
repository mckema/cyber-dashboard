# Sandbox values. No secrets here: secret values go to Secret Manager with
# gcloud secrets versions add. Placeholders marked TODO-Dn wait for an open
# decision (2026-11-09):
#   D1 = sandbox GCP project id
#   D2 = Wiki.js page id and IAP audience (OAuth client id) of wiki2
#   D3 = Linear team id
# Terraform refuses to plan while project_id is a placeholder, and refuses to
# create the job while any job input still contains "TODO-".

project_id = "TODO-D1"
region     = "europe-west4"

# Phase 1: leave null (foundation only). Phase 2: the digest ref printed by
# deploy/build-push.sh, e.g.
# "europe-west4-docker.pkg.dev/<project>/fairct/exploit-watch@sha256:<64 hex>"
image_digest = null

ew_environment    = "test"
wiki_base         = "https://wiki2.internal.ediphy.io"
wiki_page_id      = "TODO-D2"
wiki_public_url   = "https://wiki2.internal.ediphy.io/TODO-D2"
wiki_asset_folder = "exploit-watch"
iap_audience      = "TODO-D2"
linear_team_id    = "TODO-D3"

# Add "github-token" and/or "nvd-api-key" once their values exist.
optional_secrets = []

schedule         = "0 */6 * * *"
scheduler_paused = false

reports_retention_days = 30
lock_retention         = false # Bucket Lock is irreversible; never true in sandbox
enable_nat             = false
enable_cmek            = false

# Sandbox is torn down and rebuilt freely; prod keeps the default (true).
deletion_protection = false

# Team distribution address(es) only, no personal addresses, e.g.
# alert_emails = ["<team-alias>@<domain>"]
alert_emails = []

billing_account_id = ""
