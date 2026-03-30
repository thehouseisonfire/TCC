terraform {
  required_version = "= 1.13.5"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "= 1.60.1"
    }
  }
}
