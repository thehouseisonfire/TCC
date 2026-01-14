# Miri / FFI Verification Report

## Scope

This report covers Miri-based verification of the Rust FFI boundary for the Mosquitto plugin in `mqtt-auth-biscuit/`.

Goal: detect Rust undefined behavior (UB) and memory safety issues in `unsafe` code used for Mosquitto callback interfaces.

## What Was Verified

- The crate builds as both:
  - `cdylib` (Mosquitto plugin)
  - `rlib` (unit tests + Miri)

- Miri runs in CI:
  - Workflow: `.github/workflows/miri.yml`
  - Commands:
    - `cargo --config build.rustflags=[] miri setup`
    - `cargo --config build.rustflags=[] miri test`

- FFI entrypoints and callbacks (in `mqtt-auth-biscuit/src/lib.rs`) defensively handle null pointers:
  - `mosquitto_plugin_init`
  - `mosquitto_plugin_cleanup`
  - `basic_auth_callback`
  - `ext_auth_start_callback`
  - `ext_auth_continue_callback`
  - `acl_check_callback`
  - `message_callback`
  - `control_callback`

## Miri Compatibility Adjustments

- `mqtt-auth-biscuit/src/config.rs`
  - Under `cfg(miri)`, filesystem I/O is avoided for reading JWT PEM files.
  - A dummy decoding key is used to exercise initialization paths without host filesystem dependencies.

- `mqtt-auth-biscuit/src/lib.rs`
  - Under `cfg(any(test, miri))`, minimal stubs are provided for Mosquitto symbols so unit tests can run without linking against Mosquitto.

## Panic Avoidance (FFI Safety)

- `mqtt-auth-biscuit/src/cache.rs`
  - Removed `unwrap()` usage in cache construction and mutex locking.
  - `capacity=0` is clamped to a non-zero value.
  - Poisoned mutex locks are handled without panicking.

Rationale: panics must not unwind across the FFI boundary.

## How To Run Locally

From `mqtt-auth-biscuit/`:

- `cargo test`

For Miri:

- `rustup install nightly`
- `rustup component add miri --toolchain nightly`
- `cargo +nightly miri test`
