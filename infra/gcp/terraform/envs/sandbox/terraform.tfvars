# Sandbox values. No secrets here: secret values go to Secret Manager with
# gcloud secrets versions add. Values starting with TODO- are placeholders to
# fill in: the GCP project id, the Wiki.js base URL, page id and public URL, the
# IAP audience (OAuth client id of the wiki's IAP) and the Linear team id.
# Terraform refuses to plan while project_id is a placeholder, and refuses to
# create the job while any job input still contains "TODO-".

project_id = "TODO-project-id"
region     = "europe-west4"

# Phase 1: leave null (foundation only). Phase 2: the digest ref printed by
# infra/gcp/build-push.sh, e.g.
# "europe-west4-docker.pkg.dev/<project>/exploit-watch/exploit-watch@sha256:<64 hex>"
image_digest = null

ew_environment    = "test"
wiki_base         = "https://TODO-wiki-base-url"
wiki_page_id      = "TODO-wiki-page-id"
wiki_public_url   = "https://TODO-wiki-public-url"
wiki_asset_folder = "exploit-watch"
iap_audience      = "TODO-iap-audience"
linear_team_id    = "TODO-linear-team-id"

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
