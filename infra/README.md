# Benchmark Host Infrastructure

This directory is the canonical repo-local entrypoint for preparing the final
benchmark host on a paid Debian/Ubuntu server.

The current stage-1 split is:

- Terraform for VM creation and network-facing infrastructure state
- Ansible for host convergence after SSH access exists
- apt snapshots for reproducible host package resolution
- Packer deferred until repeated image rebuilds justify the extra maintenance

For the full rationale and the staged roadmap, see [`../TODO2.md`](../TODO2.md).

## Layout

The benchmark-host path is intentionally small and explicit:

- `infra/terraform/`: pinned Terraform root for creating the benchmark VM
- `infra/ansible/`: reserved for host convergence in the next step
- `scripts/benchmark_host_helper.py`: machine-readable path contract

## Current Boundary

This repo state implements only the first two steps:

- the path contract, docs, helper, and regression test
- a minimal Hetzner Terraform root for one Ubuntu 24.04 benchmark host

It does **not** yet implement:

- Ansible playbooks
- apt snapshot configuration
- Docker/package installation on the host
- benchmark execution on the host
- Packer image baking

## Terraform Scope

The Terraform root in `infra/terraform/` is intentionally minimal:

- one public Hetzner server
- one SSH key resource
- one firewall that exposes only SSH ingress
- cloud-init that creates the benchmark operator user

Terraform stops after the host is reachable over SSH as the benchmark operator.
Host setup after that point belongs to Ansible.

## Helper

Use the helper when scripts or docs need the canonical path contract:

```bash
uv run --locked python scripts/benchmark_host_helper.py
uv run --locked python scripts/benchmark_host_helper.py --json
```

## Terraform Usage

Use `HCLOUD_TOKEN` from the environment. Do not put API tokens in repo files.

Typical local flow:

```bash
cd /home/eagle/TCC2
terraform -chdir=infra/terraform init
terraform -chdir=infra/terraform plan -var-file=terraform.tfvars
terraform -chdir=infra/terraform apply -var-file=terraform.tfvars
```
