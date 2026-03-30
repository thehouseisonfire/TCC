output "server_id" {
  description = "Hetzner server ID for the benchmark host."
  value       = hcloud_server.benchmark.id
}

output "ipv4_address" {
  description = "Public IPv4 address for the benchmark host."
  value       = hcloud_server.benchmark.ipv4_address
}

output "ipv6_address" {
  description = "First public IPv6 address for the benchmark host."
  value       = hcloud_server.benchmark.ipv6_address
}

output "operator_username" {
  description = "SSH user created for benchmark operation."
  value       = var.operator_username
}

output "ssh_command" {
  description = "Convenience SSH command for the benchmark operator."
  value       = format("ssh %s@%s", var.operator_username, hcloud_server.benchmark.ipv4_address)
}

output "ansible_inventory_line" {
  description = "Single-host inventory line for the later Ansible step."
  value = format(
    "%s ansible_host=%s ansible_user=%s",
    hcloud_server.benchmark.name,
    hcloud_server.benchmark.ipv4_address,
    var.operator_username,
  )
}
