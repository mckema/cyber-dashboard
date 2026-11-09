output "bot_service_account_email" {
  description = "Job identity; the wiki2 owner grants it roles/iap.httpsResourceAccessor on the wiki's IAP backend."
  value       = module.exploit_watch.bot_service_account_email
}

output "scheduler_service_account_email" {
  description = "OAuth identity of the Cloud Scheduler trigger."
  value       = module.exploit_watch.scheduler_service_account_email
}

output "image_repository" {
  description = "Image path for build-push.sh."
  value       = module.exploit_watch.image_repository
}

output "state_bucket" {
  description = "Bucket of the job state."
  value       = module.exploit_watch.state_bucket
}

output "reports_bucket" {
  description = "Bucket of the monthly reports."
  value       = module.exploit_watch.reports_bucket
}

output "secret_ids" {
  description = "Secret ids to fill with gcloud secrets versions add."
  value       = module.exploit_watch.secret_ids
}

output "job_name" {
  description = "Cloud Run job name (null in phase 1)."
  value       = module.exploit_watch.job_name
}

output "scheduler_job_name" {
  description = "Cloud Scheduler job name (null in phase 1)."
  value       = module.exploit_watch.scheduler_job_name
}

output "nat_ip" {
  description = "Static egress IP (null unless enable_nat)."
  value       = module.exploit_watch.nat_ip
}
