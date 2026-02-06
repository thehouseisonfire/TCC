# Perf Profiling for CPU Analysis

This document describes the host-targeted kernel-level performance profiling integration using `perf` for detailed CPU performance analysis of the containerized Mosquitto broker.

## Overview

The perf profiling feature (Issue 16) provides instruction-level CPU performance analysis to understand the computational costs of JWT vs Biscuit token verification and policy evaluation. Unlike container-level metrics from cAdvisor/Prometheus, perf captures hardware-level events (cycles, instructions, cache misses) from the host kernel perspective.

## Prerequisites

### Host Requirements

- Linux kernel with perf_events support (`CONFIG_PERF_EVENTS=y`)
- `perf` tool installed (usually from `linux-tools` package)
- sudo access OR relaxed `perf_event_paranoid` settings for running perf

### Installation

```bash
# Ubuntu/Debian
sudo apt-get install linux-tools-common linux-tools-generic linux-tools-$(uname -r)

# Verify installation
perf version
perf list
```

### Permissions (sudo vs non-sudo)

By default, perf requires root privileges or specific kernel permissions. The profiling module automatically detects if sudo is required:

1. **Check current paranoid level**:
   ```bash
   cat /proc/sys/kernel/perf_event_paranoid
   ```

2. **Permission levels**:
   - `-1`: No restrictions (perf runs without sudo)
   - `0`: Allow user-space performance events
   - `1`: Allow kernel and user-space events (CAP_SYS_ADMIN needed for kernel)
   - `2`: Disallow raw tracepoint access (default on many systems)

3. **To run without sudo**, relax the paranoid setting:
   ```bash
   # Temporary (until reboot)
   sudo sysctl kernel.perf_event_paranoid=0
   
   # Permanent
   echo 'kernel.perf_event_paranoid=0' | sudo tee /etc/sysctl.d/99-perf.conf
   sudo sysctl --system
   ```

4. **Alternative: Configure sudoers** to allow passwordless perf:
   ```bash
   # Add to /etc/sudoers (use visudo)
   your_username ALL=(ALL) NOPASSWD: /usr/bin/perf
   ```

If sudo is required but not available, the profiler will log a warning and skip profiling.

## Usage

### Basic Profiling

Run perf profiling during scenario execution:

```bash
# Enable perf profiling for default key scenarios
cd mqtt-auth-biscuit
python3 benchmarks/run_scenarios.py --scenarios JWT-01,BIS-01 --perf

# Specify custom scenarios to profile
python3 benchmarks/run_scenarios.py --scenarios THUNDERING-HERD --perf --perf-scenarios THUNDERING-HERD

# Longer profiling duration for more stable results
python3 benchmarks/run_scenarios.py --scenarios POLICY-COMPLEX-25 --perf --perf-duration 30
```

### Advanced Options

```bash
# Custom events and sample rate
python3 benchmarks/run_scenarios.py --scenarios JWT-01 --perf \
  --perf-events cycles,instructions,cache-misses,cache-references \
  --perf-sample-rate 2000 \
  --perf-duration 15

# Disable callgraph recording (reduces overhead)
python3 benchmarks/run_scenarios.py --scenarios BIS-01 --perf --no-perf-callgraph

# Custom output directory
python3 benchmarks/run_scenarios.py --scenarios BASE-01 --perf \
  --perf-output-dir /tmp/perf-results
```

### CLI Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--perf` / `--no-perf` | `False` | Enable/disable perf profiling |
| `--perf-duration` | `10` | Profiling duration in seconds |
| `--perf-sample-rate` | `1000` | Sampling frequency in Hz |
| `--perf-events` | `cycles,instructions,cache-misses` | Comma-separated event list |
| `--perf-callgraph` / `--no-perf-callgraph` | `True` | Record call graphs |
| `--perf-scenarios` | `None` | Comma-separated scenario IDs to profile (default: key scenarios) |
| `--perf-output-dir` | `benchmarks/results/perf` | Directory for perf data files |

## Default Profiled Scenarios

By default, the following scenarios are profiled when `--perf` is enabled:

- `BASE-01` - Baseline without authentication
- `JWT-01` - JWT token verification baseline
- `BIS-01` - Biscuit token verification baseline
- `POLICY-COMPLEX-1` - Single block Biscuit complexity
- `POLICY-COMPLEX-5` - Medium block chain complexity
- `POLICY-COMPLEX-25` - High block chain complexity
- `POLICY-COMPLEX-LOW` - Low Datalog complexity
- `POLICY-COMPLEX-MED` - Medium Datalog complexity
- `POLICY-COMPLEX-HIGH` - High Datalog complexity
- `THUNDERING-HERD` - Connection burst CPU load

To profile specific scenarios only, use `--perf-scenarios`:

```bash
python3 benchmarks/run_scenarios.py --scenarios A,B,C,D --perf --perf-scenarios B,D
```

## Output Format

### JSON Results

Perf profiling results are included in scenario output JSON under `perf_profiling` and per-run `perf` sections:

```json
{
  "scenario": "JWT-01",
  "perf_profiling": {
    "enabled": true,
    "config": {
      "duration": 10,
      "sample_rate": 1000,
      "events": ["cycles", "instructions", "cache-misses"],
      "callgraph": true
    },
    "status": {
      "enabled": true,
      "installed": true,
      "version": "perf version 6.2.0"
    }
  },
  "runs": [{
    "loadgen": {...},
    "resources": {...},
    "perf": {
      "success": true,
      "container_pid": 12345,
      "mosquitto_process": {
        "pid": 12346,
        "command": "mosquitto -c /mosquitto/config/mosquitto.conf"
      },
      "perf_stat": {
        "events": {
          "cycles": 1250000000,
          "instructions": 2500000000,
          "cache-misses": 5000000
        },
        "cycles_per_instruction": 0.50,
        "cache_miss_rate": 2.5,
        "duration_seconds": 10.0
      }
    }
  }]
}
```

### Key Metrics

- **cycles**: CPU cycles consumed during profiling
- **instructions**: Instructions retired
- **cache-misses**: L1/L2/L3 cache misses (depending on PMU)
- **cycles_per_instruction (CPI)**: Lower is better (typical: 0.2-1.0)
- **cache_miss_rate**: Percentage of cache accesses that miss (typical: 1-10%)

### Perf Data Files

When `--perf-callgraph` is enabled (default), additional files are generated:

- `perf-{pid}-{timestamp}.data` - Raw perf recording (for `perf report`)
- `perf-{pid}-{timestamp}.script` - Symbolic call stacks

Analyze manually:

```bash
# View annotated source
cd benchmarks/results/perf
perf report -i perf-12345-1234567890.data

# Generate flame graph (requires flamegraph.pl)
perf script -i perf-12345-1234567890.data | ./stackcollapse-perf.pl | ./flamegraph.pl > flame.svg
```

## Interpreting Results

### CPI Analysis

| CPI Range | Interpretation |
|-----------|----------------|
| < 0.4 | Excellent (highly efficient, likely memory-bound or idle) |
| 0.4 - 0.7 | Good (efficient execution) |
| 0.7 - 1.0 | Moderate (some stalls) |
| > 1.0 | Poor (significant stalls, branch mispredictions, cache misses) |

### JWT vs Biscuit Comparison

Expect to see:

- **JWT verification**: Lower CPI (cryptographic libraries highly optimized)
- **Biscuit verification**: Potentially higher CPI due to:
  - Datalog evaluation overhead
  - Additional block parsing
  - Ed25519 signature verification (pure Rust vs optimized C/Assembly)

### Cache Behavior

Higher cache miss rates in Biscuit scenarios indicate:
- Datalog working set larger than L1/L2 cache
- Irregular memory access patterns during policy evaluation

## Troubleshooting

### "perf not installed"

```bash
# Install perf for your kernel version
sudo apt-get install linux-tools-$(uname -r)
```

### "Permission denied" / "You may not have permission to collect stats"

Perf requires root or adjusted perf_event_paranoid:

```bash
# Temporary (until reboot)
sudo sh -c 'echo 1 > /proc/sys/kernel/perf_event_paranoid'

# Permanent
sudo sysctl kernel.perf_event_paranoid=1
```

### Container PID not found

Ensure the container is running:

```bash
docker ps | grep mosquitto
```

### No events counted

Some events may not be available on all CPUs. Check available events:

```bash
perf list
```

## Methodology Notes

### Why Host-Level Profiling?

Container-level metrics (from cAdvisor) measure resource consumption from the cgroup perspective but miss:
- Hardware counter events (cycles, instructions)
- Cache hierarchy behavior
- Branch prediction efficiency
- Pipeline stalls

Host-level `perf` directly accesses the CPU's Performance Monitoring Unit (PMU) for accurate low-level metrics.

### Profiling Overhead

- **perf stat**: ~1-2% overhead (minimal, recommended for all runs)
- **perf record** (with callgraph): ~5-10% overhead (use selectively)

### Reproducibility

For consistent results:
- Pin Mosquitto to specific CPUs via `cpuset` in docker-compose.yml
- Disable CPU frequency scaling:
  ```bash
  sudo cpupower frequency-set -g performance
  ```
- Run multiple iterations and average results

## Integration with Analysis

Use perf data in aggregate analysis:

```python
from benchmarks.aggregate_results import load_results

results = load_results("benchmarks/results")
for r in results:
    if "perf" in r and r["perf"].get("success"):
        cpi = r["perf"]["perf_stat"]["cycles_per_instruction"]
        print(f"{r['scenario']}: CPI={cpi:.2f}")
```

## References

- [ARTICLE.md](../ARTICLE.md) - Research methodology and hypotheses
- [PERF-VERSION(1)](https://man7.org/linux/man-pages/man1/perf.1.html) - perf man page
- [Intel 64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) - PMU events documentation
