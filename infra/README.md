# Benchmark Host Infrastructure

Terraform provisions the benchmark VM. Ansible configures the host and runs
smoke checks using pinned Ubuntu package snapshots. The benchmark checkout,
build, and execution steps are documented in the [run plan](../RUN.md).

## Layout

- `infra/terraform/` provisions one Ubuntu 24.04 benchmark VM on Hetzner.
- `infra/ansible/` configures and verifies the host over SSH.
- The repository's `scripts/` launch the benchmark-host tools implemented in
  `tools/`.

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
./scripts/benchmark-host-smoke --inventory infra/ansible/inventory.yml
```

To rerun verification without applying changes again:

```bash
./scripts/benchmark-host-smoke --inventory infra/ansible/inventory.yml --verify-only
```

The smoke path applies `infra/ansible/playbook.yml` and then runs the separate
verification playbook `infra/ansible/verify.yml`.

## Helper

Use the helper when scripts or docs need the canonical path contract:

```bash
./scripts/benchmark-host-helper
./scripts/benchmark-host-helper --json
```

Each launcher in `scripts/` is a thin bash wrapper around the corresponding
crate in `tools/`. That keeps the repo-local command surface stable while the
implementation and tests live in dedicated Rust tool crates.

## Terraform Usage

Use `HCLOUD_TOKEN` from the environment. Do not put API tokens in repo files.

Typical local flow:

```bash
terraform -chdir=infra/terraform init
terraform -chdir=infra/terraform plan -var-file=terraform.tfvars
terraform -chdir=infra/terraform apply -var-file=terraform.tfvars
```

## Ansible Usage

Generate the live inventory from Terraform outputs:

```bash
./scripts/render-benchmark-inventory --from-terraform > infra/ansible/inventory.yml
```

Then converge the host:

```bash
cd infra/ansible
uv run --locked --group dev ansible-playbook -i inventory.yml playbook.yml
```

Or run the combined converge-and-verify smoke path from the repo root:

```bash
./scripts/benchmark-host-smoke --inventory infra/ansible/inventory.yml
```

## Tooling Commands

The benchmark-host tooling now has two stable entry styles:

- preferred operator entrypoint: `./scripts/<tool-name>`
- direct implementation entrypoint: `cargo run --locked -p <tool-package> --bin <tool-name> -- ...`

Available launchers:

- `./scripts/benchmark-host-helper`
- `./scripts/benchmark-host-smoke`
- `./scripts/check-pins`
- `./scripts/render-benchmark-inventory`

Use the `scripts/` launchers in docs, shell workflows, and ad hoc local runs.
Use direct Cargo commands when you need explicit Rust crate targeting.

The committed `inventory.example.yml` exists only as a syntax-checkable example.
Do not edit a real inventory into the repository.

## Snapshot Pinning

Ubuntu 24.04 already uses the supported snapshot-aware apt path. This repo pins
the host by writing `APT::Snapshot "<timestamp>";` under
`/etc/apt/apt.conf.d/`, rather than mutating source stanzas directly.

The exact package versions committed under `infra/ansible/group_vars/all/` are
intentionally coupled to that snapshot timestamp. Update them together.
