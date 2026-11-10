# Exact versions for this environment. .terraform.lock.hcl (committed) pins the
# provider build and its checksums for linux_amd64, windows_amd64, darwin_arm64.
terraform {
  required_version = "~> 1.16"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.8.0"
    }
  }
}
