# Perf Profiling Guide

This document is the perf-specific companion to
`RUNNING_BENCHMARKS.md`.

- Benchmark execution workflow and scenario orchestration: `RUNNING_BENCHMARKS.md`
- Project status and issue tracking: `../PROGRESS.md`

## Scope

Use this file for host-level perf concerns only:

- Linux perf prerequisites and permissions
- perf-specific CLI flags and output layout
- CPU-counter interpretation (CPI/cache behavior)
- perf troubleshooting

## Host Prerequisites

- Linux kernel with `perf_events` support (`CONFIG_PERF_EVENTS=y`)
- `perf` installed (typically via linux-tools)
- Privileges to read PMU counters (root, sudo, or relaxed `perf_event_paranoid`)

Install on Ubuntu/Debian:

```bash
sudo apt-get install linux-tools-common linux-tools-generic linux-tools-$(uname -r)
perf version
perf list
```

## Permissions

Check current policy:

```bash
cat /proc/sys/kernel/perf_event_paranoid
```

Typical values:

- `-1`: least restrictive
- `0`: user-space perf events allowed
- `1`: tighter kernel access
- `2`: restrictive default on many hosts

Temporary relaxation:

```bash
sudo sysctl kernel.perf_event_paranoid=0
```

Persistent relaxation:

```bash
echo 'kernel.perf_event_paranoid=0' | sudo tee /etc/sysctl.d/99-perf.conf
sudo sysctl --system
```

Optional sudoers approach:

```text
your_username ALL=(ALL) NOPASSWD: /usr/bin/perf
```

## Perf Flags (Run Scenarios)

Run commands are documented in `RUNNING_BENCHMARKS.md`; perf controls are:

| Option | Default | Meaning |
|---|---|---|
| `--perf` / `--no-perf` | `False` | Enable/disable perf profiling |
| `--perf-duration` | `10` | Profiling duration (seconds) |
| `--perf-sample-rate` | `1000` | Sampling frequency (Hz) |
| `--perf-events` | `cycles,instructions,cache-misses` | Event list |
| `--perf-callgraph` / `--no-perf-callgraph` | `True` | Capture call graph data |
| `--perf-scenarios` | `None` | Scenario subset to profile |
| `--perf-output-dir` | `benchmarks/results/perf` | Output directory |

Minimal example:

```bash
python3 benchmarks/run_scenarios.py --scenarios JWT-01,BIS-01 --perf
```

## Output Structure

Perf metadata appears in scenario output JSON:

- top-level `perf_profiling` section (config/status)
- per-run `perf` section (measured counters)

Key fields:

- `events.cycles`
- `events.instructions`
- `events.cache-misses`
- `cycles_per_instruction`
- `cache_miss_rate`

When callgraph is enabled, files are written under `benchmarks/results/perf`:

- `perf-<pid>-<timestamp>.data`
- `perf-<pid>-<timestamp>.script`

Manual inspection:

```bash
cd benchmarks/results/perf
perf report -i perf-<pid>-<timestamp>.data
```

## Interpreting CPU Counters

CPI ranges (rule of thumb):

- `< 0.4`: very efficient
- `0.4 - 0.7`: good
- `0.7 - 1.0`: moderate stalls
- `> 1.0`: significant stalls/memory pressure

Interpretation guidance:

- Higher CPI can indicate pipeline stalls, branch misses, or cache pressure.
- Higher cache miss rates can indicate larger or less-local policy working sets.
- Compare JWT/Biscuit under the same scenario, load, and pinning settings.

## Troubleshooting

`perf not installed`:

```bash
sudo apt-get install linux-tools-$(uname -r)
```

`Permission denied` / cannot collect stats:

```bash
sudo sysctl kernel.perf_event_paranoid=0
```

No Mosquitto PID / empty samples:

- Ensure broker container is running (`docker ps`)
- Ensure selected events exist on host PMU (`perf list`)
- Increase profiling window (`--perf-duration`)

## Reproducibility Notes

- Keep CPU pinning stable for broker/load generator.
- Prefer fixed CPU governor during measurement windows.
- Repeat runs and compare distributions, not single values.

## References

- `RUNNING_BENCHMARKS.md`
- `../PROGRESS.md`
- `../ARTICLE.md`
- `man perf`
