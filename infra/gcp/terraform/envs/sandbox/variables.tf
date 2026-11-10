# Pass-through inputs; see the module's variables.tf for validations and the
# full list (inputs not listed here use the module defaults).

variable "project_id" {
  description = "Sandbox GCP project id."
  type        = string
}

variable "region" {
  description = "Region of every regional resource."
  type        = string
  default     = "europe-west4"
}

variable "image_digest" {
  description = "Image by digest from build-push.sh; null = phase 1 (foundation only)."
  type        = string
  default     = null
}

variable "ew_environment" {
  description = "Data marking of report PDFs (test or production)."
  type        = string
  default     = "test"
}

variable "wiki_base" {
  description = "Wiki.js base URL."
  type        = string
}

variable "wiki_page_id" {
  description = "Id of the Wiki.js page the job updates."
  type        = string
}

variable "wiki_public_url" {
  description = "The page as a browser sees it."
  type        = string
}

variable "wiki_asset_folder" {
  description = "Wiki.js asset folder for the report PDFs."
  type        = string
  default     = "exploit-watch"
}

variable "iap_audience" {
  description = "OAuth client id of the wiki's IAP."
  type        = string
}

variable "linear_team_id" {
  description = "Linear team id."
  type        = string
}

variable "optional_secrets" {
  description = "Optional secrets: github-token, nvd-api-key."
  type        = list(string)
  default     = []
}

variable "schedule" {
  description = "Cron schedule of the trigger."
  type        = string
  default     = "0 */6 * * *"
}

variable "scheduler_paused" {
  description = "Create the trigger paused."
  type        = bool
  default     = false
}

variable "reports_retention_days" {
  description = "Retention period of the reports bucket, in days."
  type        = number
  default     = 30
}

variable "lock_retention" {
  description = "Lock the reports retention policy (irreversible)."
  type        = bool
  default     = false
}

variable "enable_nat" {
  description = "Static egress IP through Cloud NAT."
  type        = bool
  default     = false
}

variable "enable_cmek" {
  description = "Customer-managed encryption keys for buckets and secrets."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Terraform deletion guards on the job, secrets, buckets and registry."
  type        = bool
  default     = true
}

variable "alert_emails" {
  description = "Alert recipients."
  type        = list(string)
  default     = []
}

variable "billing_account_id" {
  description = "Billing account for the optional budget alert; empty = none."
  type        = string
  default     = ""
}
