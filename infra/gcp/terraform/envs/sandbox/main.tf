locals {
  env = "sandbox"

  # Labels of every labelable resource: given to the module (which adds env) and
  # applied by the provider, including to any resource added outside the module.
  labels = {
    app        = "exploit-watch"
    managed-by = "terraform"
  }
}

module "exploit_watch" {
  source = "../../modules/exploit-watch"

  project_id = var.project_id
  region     = var.region
  env        = local.env
  labels     = local.labels

  image_digest      = var.image_digest
  ew_environment    = var.ew_environment
  wiki_base         = var.wiki_base
  wiki_page_id      = var.wiki_page_id
  wiki_public_url   = var.wiki_public_url
  wiki_asset_folder = var.wiki_asset_folder
  iap_audience      = var.iap_audience
  linear_team_id    = var.linear_team_id
  optional_secrets  = var.optional_secrets

  schedule         = var.schedule
  scheduler_paused = var.scheduler_paused

  reports_retention_days = var.reports_retention_days
  lock_retention         = var.lock_retention
  enable_nat             = var.enable_nat
  enable_cmek            = var.enable_cmek
  deletion_protection    = var.deletion_protection

  alert_emails       = var.alert_emails
  billing_account_id = var.billing_account_id
}
