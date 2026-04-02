# Benchmark Host Reproducibility TODO

## Summary

The project should define a clean, repo-controlled path for preparing the final
benchmark host on Debian/Ubuntu without overcommitting to a heavy image-baking
pipeline too early.

The immediate target is:

- a canonical repo layout for host provisioning work
- a documented recommendation for the tool split
- a small helper that exposes those canonical paths for humans and automation
- a regression test that keeps the helper/doc path stable

This document intentionally does **not** implement the full infrastructure
stack. It defines the rationale, requirements, and tests that should guide that
work.

## Goal

Add a benchmark-host reproducibility path that is:

- explicit
- repo-local
- easy to discover
- testable
- compatible with the existing pinned application/container toolchain

The intended stage-1 stack is:

1. Terraform for VM/network provisioning when infra recreation is needed
2. Ansible for host configuration
3. Ubuntu/Debian package snapshots for pinned host package resolution
4. Packer deferred until repeated image rebuilds justify the extra maintenance

## Rationale

### Why this should exist in-repo

The repository already pins application dependencies, container digests, Rust
toolchains, and CI actions.

What is still outside that control boundary is the final benchmark host:

- VM creation
- apt repository snapshot selection
- Docker engine / Compose installation policy
- host sysctls / CPU governor / perf tooling
- benchmark operator workflow

If the final measurements are run on a paid Debian/Ubuntu server, those steps
need a canonical repo path rather than living in ad hoc notes or terminal
history.

### Why Terraform + Ansible is the preferred starting split

Terraform is a good fit for infra state:

- server instance
- disk
- network
- firewall
- static IP

Ansible is a better fit for host convergence:

- apt snapshot configuration
- exact package installation
- Docker setup
- user/group setup
- benchmark prerequisites
- repo checkout and run commands

### Why Packer is not stage 1

Packer is useful later, but it adds:

- an image build pipeline
- extra artifact lifecycle management
- slower edit/debug loops
- more maintenance overhead while the host recipe is still changing

For the first clean implementation, documenting the path and keeping it stable is
more important than baking immutable images immediately.

## Canonical Repo Path

The benchmark-host provisioning path should live under:

- `infra/terraform/`
- `infra/ansible/`
- `infra/README.md`

The planning/spec document for that path should remain:

- `TODO2.md`

The repo helper that reports those canonical paths should live at:

- `scripts/benchmark_host_helper.py`

## Implementation Requirements

### Helper requirements

Add a small helper that:

- resolves the repository root deterministically
- returns the canonical benchmark-host paths
- exposes the recommended stage-1 stack in one place
- supports both human-readable and machine-readable output

The helper should not:

- create infrastructure
- require Ansible/Terraform/Packer to be installed
- mutate repo state

### Documentation requirements

Add concise documentation that:

- explains the canonical `infra/` layout
- explains why Terraform and Ansible are split
- states that Packer is intentionally deferred
- points readers to `TODO2.md` for the full rationale
- points readers to the helper for the canonical path output

### Scaffold requirements

Add the minimal directory scaffold:

- `infra/terraform/`
- `infra/ansible/`

This is to make the intended path discoverable now, even before the provisioning
code exists.

## Test Requirements

### Required automated test

Add a unit test for the helper that verifies:

- the helper resolves the repo root correctly
- the helper returns the expected canonical relative paths
- the helper's JSON output includes the Terraform, Ansible, infra README, and
  TODO document paths
- the helper continues to describe Packer as deferred rather than mandatory

### Recommended CI coverage

Run that unit test in the existing Python CI path so the documented benchmark
host layout cannot drift silently.

## Implementation Sequence

1. Add the repo structure and docs only. (Completed)
2. Add Terraform for VM creation, pinned and minimal. (Completed)
3. Add Ansible for host convergence on an already-created VM. (Completed)
4. Add apt snapshot pinning and exact package versions. (Completed)
5. Add a smoke path that proves a fresh host reaches the expected baseline. (Completed)
6. Add the benchmark-specific setup and verification tests. (Completed)

## Follow-on Work

The later implementation should add:

1. Terraform module(s) for the benchmark server
2. Ansible playbook(s) for host convergence
3. apt snapshot date/config handling
4. exact Docker/package setup for the host
5. benchmark run entrypoints
6. optional Packer image baking only if repeated rebuilds justify it
