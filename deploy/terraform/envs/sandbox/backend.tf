# State bucket created by deploy/bootstrap.sh (versioning, uniform access,
# public access prevention). If bootstrap.sh printed another name, override it:
#   terraform init -backend-config="bucket=<name>"
terraform {
  backend "gcs" {
    bucket = "exploit-watch-tfstate-sandbox"
    prefix = "exploit-watch/sandbox"
  }
}
