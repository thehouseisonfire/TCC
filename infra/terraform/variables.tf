variable "name_prefix" {
  description = "Resource name prefix for the benchmark host."
  type        = string
  default     = "tcc2-bench"
}

variable "location" {
  description = "Hetzner location for the benchmark server, for example fsn1 or hel1."
  type        = string
}

variable "server_type" {
  description = "Hetzner server type for the benchmark host, for example cpx21."
  type        = string
}

variable "image" {
  description = "Hetzner image name for the benchmark server."
  type        = string
  default     = "ubuntu-24.04"
}

variable "operator_username" {
  description = "Linux user created by cloud-init for benchmark operation."
  type        = string
  default     = "benchmark"
}

variable "operator_ssh_public_key" {
  description = "SSH public key for the benchmark operator user."
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH on the benchmark host."
  type        = list(string)
}

variable "labels" {
  description = "Additional Hetzner labels to merge onto created resources. Built-in managed-by, repo, and role labels are always applied, null is treated the same as omitting this input, and caller-supplied values override defaults on key collision."
  type        = map(string)
  default     = {}
}
