# Benchmark Host Infrastructure

This directory is the canonical repo-local entrypoint for preparing and smoke
verifying the final benchmark host on a paid Debian/Ubuntu server.

The current stage-1 split is:

- Terraform for VM creation and network-facing infrastructure state
- Ansible for host convergence after SSH access exists
- apt snapshots for reproducible host package resolution
- Packer deferred until repeated image rebuilds justify the extra maintenance

For the full rationale and the staged roadmap, see [`../TODO2.md`](../TODO2.md).

## Layout

The benchmark-host path is intentionally small and explicit:

- `infra/terraform/`: pinned Terraform root for creating the benchmark VM
- `infra/ansible/`: host convergence for the already-created benchmark VM
- `scripts/benchmark_host_helper.py`: machine-readable path contract

## Current Boundary

This repo state implements the first six steps in the staged host path:

- the path contract, docs, helper, and regression test
- a minimal Hetzner Terraform root for one Ubuntu 24.04 benchmark host
- Ansible convergence for the Terraform-created Ubuntu 24.04 host
- Ubuntu snapshot pinning plus exact apt package locks for the host baseline
- a smoke path that proves a fresh host reaches the expected baseline
- benchmark prerequisite installation plus verification coverage

It does **not** yet implement:

- repo checkout on the host
- plugin or token builds on the host
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

## Ansible Scope

The Ansible root currently targets only Ubuntu 24.04 hosts created by the
Terraform root in this repository.

It intentionally covers only the reproducible host baseline needed for later
benchmark work:

- pin apt to one Ubuntu snapshot with `APT::Snapshot`
- install a small exact-version apt baseline
- install Docker from the same pinned snapshot
- disable unattended apt timers that would perturb later measurements

It now also installs the benchmark prerequisite toolchain needed before a later
repo checkout/build step:

- `uv 0.9.17`
- managed Python `3.14.2` via `uv`
- Rust `1.93.1` with `clippy` and `rustfmt`
- Linux `perf` tooling with `kernel.perf_event_paranoid=0`

It intentionally does **not** yet clone this repository onto the host, build
the plugin, generate tokens, or start benchmark containers. Those remain the
next follow-on layer above the reproducible host baseline.

## Smoke Path

After Terraform has created the host and inventory has been rendered, use the
repo-local smoke path to converge and verify the machine:

```bash
uv run --locked python scripts/benchmark_host_smoke.py --inventory infra/ansible/inventory.yml
```

To rerun verification without applying changes again:

```bash
uv run --locked python scripts/benchmark_host_smoke.py --inventory infra/ansible/inventory.yml --verify-only
```

The smoke path applies `infra/ansible/playbook.yml` and then runs the separate
verification playbook `infra/ansible/verify.yml`.

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

## Ansible Usage

Generate the live inventory from Terraform outputs:

```bash
uv run --locked python scripts/render_benchmark_inventory.py --from-terraform > infra/ansible/inventory.yml
```

Then converge the host:

```bash
cd infra/ansible
uv run --locked --group dev ansible-playbook -i inventory.yml playbook.yml
```

Or run the combined converge-and-verify smoke path from the repo root:

```bash
uv run --locked python scripts/benchmark_host_smoke.py --inventory infra/ansible/inventory.yml
```

The committed `inventory.example.yml` exists only as a syntax-checkable example.
Do not edit a real inventory into the repository.

## Snapshot Pinning

Ubuntu 24.04 already uses the supported snapshot-aware apt path. This repo pins
the host by writing `APT::Snapshot "<timestamp>";` under
`/etc/apt/apt.conf.d/`, rather than mutating source stanzas directly.

The exact package versions committed under `infra/ansible/group_vars/all/` are
intentionally coupled to that snapshot timestamp. Update them together.
