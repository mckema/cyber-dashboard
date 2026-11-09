# Credentials: Application Default Credentials of the operator
# (gcloud auth application-default login). No service account keys.
provider "google" {
  project = var.project_id
  region  = var.region

  # Bill API quota to this project (needed by the Billing Budgets API with
  # user credentials).
  billing_project       = var.project_id
  user_project_override = true

  default_labels = local.labels
}
