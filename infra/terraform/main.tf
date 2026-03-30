provider "hcloud" {}

locals {
  server_name = "${var.name_prefix}-host"
  default_labels = {
    "managed-by" = "terraform"
    "repo"       = "TCC2"
    "role"       = "benchmark-host"
  }
  labels = merge(local.default_labels, coalesce(var.labels, {}))
}

resource "hcloud_ssh_key" "operator" {
  name       = "${var.name_prefix}-operator"
  public_key = trimspace(var.operator_ssh_public_key)
  labels     = local.labels
}

resource "hcloud_firewall" "benchmark" {
  name   = "${var.name_prefix}-ssh"
  labels = local.labels

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.allowed_ssh_cidrs
    description = "Allow SSH access to the benchmark operator"
  }

  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Allow outbound TCP traffic"
  }

  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "any"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Allow outbound UDP traffic"
  }

  rule {
    direction       = "out"
    protocol        = "icmp"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Allow outbound ICMP traffic"
  }
}

resource "hcloud_server" "benchmark" {
  name         = local.server_name
  image        = var.image
  server_type  = var.server_type
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.operator.id]
  firewall_ids = [hcloud_firewall.benchmark.id]
  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    operator_username       = var.operator_username
    operator_ssh_public_key = trimspace(var.operator_ssh_public_key)
  })
  labels                   = local.labels
  backups                  = false
  delete_protection        = false
  rebuild_protection       = false
  shutdown_before_deletion = true

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
}
