"""Host-targeted kernel-level performance profiling with perf.

This module provides CPU performance analysis capabilities for the containerized
Mosquitto broker process during token verification and policy evaluation.
It enables instruction-level profiling to understand computational costs of
JWT vs Biscuit verification while maintaining container isolation.

Based on Issue 16 requirements from PROGRESS.md:
- Host-level perf installation and configuration
- Container PID discovery mechanism
- CPU cycle, instruction, and cache miss data collection
- Performance profiling data included in scenario results
- Analysis correlating perf data with token type and policy complexity
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from benchmarks.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class PerfConfig:
    """Configuration for perf profiling.

    Attributes:
        events: List of perf events to sample (e.g., cycles, instructions, cache-misses)
        sample_rate: Sampling frequency in Hz (default: 1000)
        duration: Profiling duration in seconds (default: 10)
        output_dir: Directory to store perf data files
        record_callgraph: Whether to record call graph (-g flag)
        record_cpu: CPU to pin profiler to (optional)
    """

    events: list[str] = field(
        default_factory=lambda: ["cycles", "instructions", "cache-misses", "cache-references"]
    )
    sample_rate: int = 1000
    duration: int = 10
    output_dir: str = "benchmarks/results/perf"
    record_callgraph: bool = True
    record_cpu: int | None = None


@dataclass
class PerfResult:
    """Result from a perf profiling session.

    Attributes:
        events: Dictionary of event names to their sampled counts
        cycles_per_instruction: CPI ratio (cycles / instructions)
        cache_miss_rate: Cache miss rate (cache-misses / cache-references * 100)
        duration_seconds: Actual profiling duration
        pid: Process ID that was profiled
        container_id: Docker container ID
        command: Command that was profiled
        error: Error message if profiling failed
        raw_data: Raw perf stat output for debugging
    """

    events: dict[str, int] = field(default_factory=dict)
    cycles_per_instruction: float | None = None
    cache_miss_rate: float | None = None
    duration_seconds: float = 0.0
    pid: int | None = None
    container_id: str | None = None
    command: str | None = None
    error: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)


def check_perf_installation() -> dict[str, Any]:
    """Check if perf is installed and available on the host.

    Returns:
        Dictionary with installation status and version info
    """
    result: dict[str, Any] = {
        "installed": False,
        "version": None,
        "path": None,
        "capabilities": [],
        "error": None,
    }

    try:
        # Find perf binary (may be versioned as perf_5.10, perf_6.1, etc.)
        perf_path = _find_perf_binary()
        if not perf_path:
            result["error"] = "perf not found in PATH"
            return result

        result["path"] = perf_path

        # Check version
        version_result = subprocess.run(
            [perf_path, "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if version_result.returncode == 0:
            result["version"] = version_result.stdout.strip()
            result["installed"] = True

        # Check capabilities by listing available events
        events_result = subprocess.run(
            [perf_path, "list", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if events_result.returncode == 0:
            try:
                events_data = json.loads(events_result.stdout)
                # Extract common hardware events we care about
                hw_events = [
                    e
                    for e in events_data
                    if e.get("event")
                    in {
                        "cycles",
                        "instructions",
                        "cache-misses",
                        "cache-references",
                        "branch-misses",
                        "branches",
                        "stalled-cycles-frontend",
                        "stalled-cycles-backend",
                    }
                ]
                result["capabilities"] = [e.get("event") for e in hw_events if e.get("event")]
            except json.JSONDecodeError:
                # Fallback: try to parse text output
                pass

        return result

    except subprocess.TimeoutExpired:
        result["error"] = "perf version check timed out"
        return result
    except Exception as e:
        result["error"] = f"Error checking perf: {e}"
        return result


def _find_perf_binary() -> str | None:
    """Find the perf binary on the system.

    Returns:
        Path to perf binary, or None if not found
    """
    # Try common perf binary names
    perf_names = ["perf"]

    # Try versioned perf binaries (e.g., perf_5.10 for kernel 5.10)
    try:
        kernel_version = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if kernel_version.returncode == 0:
            kernel = kernel_version.stdout.strip()
            # Extract major.minor version
            match = re.match(r"(\d+\.\d+)", kernel)
            if match:
                perf_names.insert(0, f"perf_{match.group(1)}")
    except Exception:
        pass

    for name in perf_names:
        try:
            which_result = subprocess.run(
                ["which", name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if which_result.returncode == 0:
                return which_result.stdout.strip()
        except Exception:
            continue

    return None


def _check_perf_permissions(perf_path: str) -> dict[str, Any]:
    """Check if perf can run without sudo by testing permissions.

    Args:
        perf_path: Path to perf binary

    Returns:
        Dictionary with permission status and recommendations
    """
    result: dict[str, Any] = {
        "needs_sudo": True,
        "paranoid_level": None,
        "test_result": None,
        "error": None,
    }

    # Check kernel.perf_event_paranoid setting
    try:
        with open("/proc/sys/kernel/perf_event_paranoid", encoding="utf-8") as f:
            level = int(f.read().strip())
            result["paranoid_level"] = level
            # Level -1: no restrictions
            # Level 0: allow user-space performance events
            # Level 1: allow kernel and user-space events (CAP_SYS_ADMIN for kernel)
            # Level 2: disallow raw tracepoint access
            if level <= 0:
                result["needs_sudo"] = False
    except (FileNotFoundError, PermissionError, ValueError) as e:
        result["error"] = f"Could not read perf_event_paranoid: {e}"

    # Test if perf works without sudo
    try:
        test_result = subprocess.run(
            [perf_path, "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["test_result"] = test_result.returncode == 0
        if test_result.returncode == 0:
            result["needs_sudo"] = False
    except Exception as e:
        result["error"] = f"Could not test perf without sudo: {e}"

    return result


def _build_perf_cmd(
    perf_path: str,
    subcommand: str,
    needs_sudo: bool,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build perf command with optional sudo.

    Args:
        perf_path: Path to perf binary
        subcommand: perf subcommand (stat, record, etc.)
        needs_sudo: Whether to prefix with sudo
        extra_args: Additional arguments for the subcommand

    Returns:
        Command list ready for subprocess
    """
    cmd = ["sudo", perf_path] if needs_sudo else [perf_path]
    cmd.append(subcommand)
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def get_container_pid(container_name: str) -> int | None:
    """Get the host PID of the main process in a Docker container.

    Args:
        container_name: Docker container name or ID

    Returns:
        Host PID of the container's main process, or None if not found
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            pid = int(result.stdout.strip())
            logger.debug("Found PID %d for container %s", pid, container_name)
            return pid
        else:
            logger.warning("Failed to get PID for container %s: %s", container_name, result.stderr)
            return None
    except subprocess.TimeoutExpired:
        logger.error("Timeout getting PID for container %s", container_name)
        return None
    except ValueError:
        logger.error("Invalid PID output for container %s", container_name)
        return None
    except Exception as e:
        logger.error("Error getting container PID: %s", e)
        return None


def find_mosquitto_process(container_pid: int) -> dict[str, Any] | None:
    """Find the Mosquitto broker process within a container namespace.

    Args:
        container_pid: Host PID of the container's init process

    Returns:
        Dictionary with mosquitto process info, or None if not found
    """
    try:
        # Look for mosquitto processes in the container namespace
        # Using nsenter to enter the container's PID namespace
        result = subprocess.run(
            ["sudo", "nsenter", "-t", str(container_pid), "-p", "pgrep", "-a", "mosquitto"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            for line in lines:
                parts = line.split(None, 1)  # Split into PID and command
                if len(parts) >= 1:
                    try:
                        pid = int(parts[0])
                        command = parts[1] if len(parts) > 1 else "mosquitto"
                        # Filter out grep itself and other non-mosquitto processes
                        if "mosquitto" in command and "grep" not in command:
                            return {
                                "pid": pid,
                                "command": command,
                                "namespace_pid": pid,  # In container namespace
                            }
                    except ValueError:
                        continue

        # Fallback: check /proc to find mosquitto
        # The container PID is the host PID of the container's init
        # We need to find child processes
        result = subprocess.run(
            ["pgrep", "-P", str(container_pid), "mosquitto"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            pids = [int(p) for p in result.stdout.strip().split("\n") if p]
            if pids:
                return {
                    "pid": pids[0],
                    "command": "mosquitto",
                    "namespace_pid": None,
                }

        return None

    except subprocess.TimeoutExpired:
        logger.error("Timeout finding mosquitto process")
        return None
    except Exception as e:
        logger.error("Error finding mosquitto process: %s", e)
        return None


def run_perf_stat(
    target_pid: int,
    config: PerfConfig | None = None,
) -> PerfResult:
    """Run perf stat to collect performance counter data.

    Args:
        target_pid: Process ID to profile
        config: Perf configuration (uses defaults if None)

    Returns:
        PerfResult with collected metrics
    """
    if config is None:
        config = PerfConfig()

    result = PerfResult(pid=target_pid)
    perf_path = _find_perf_binary()

    if not perf_path:
        result.error = "perf binary not found"
        return result

    # Check if we need sudo for perf
    perm_check = _check_perf_permissions(perf_path)
    needs_sudo = perm_check.get("needs_sudo", True)
    if not needs_sudo:
        logger.debug(
            "perf can run without sudo (paranoid level: %s)", perm_check.get("paranoid_level")
        )

    # Create output directory
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique output file
    timestamp = int(time.time())
    output_file = output_dir / f"perf-{target_pid}-{timestamp}.json"

    # Build perf stat command
    cmd = _build_perf_cmd(
        perf_path,
        "stat",
        needs_sudo,
        [
            "-p",
            str(target_pid),
            "-o",
            str(output_file),
            "-x",
            ",",  # CSV format
        ],
    )

    # Add events
    for event in config.events:
        cmd.extend(["-e", event])

    # Add duration
    cmd.extend(["--", "sleep", str(config.duration)])

    logger.info(
        "Starting perf profiling on PID %d for %d seconds (events: %s)",
        target_pid,
        config.duration,
        ", ".join(config.events),
    )

    try:
        start_time = time.time()
        perf_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.duration + 30,
        )
        result.duration_seconds = time.time() - start_time

        if perf_result.returncode != 0:
            result.error = f"perf stat failed: {perf_result.stderr}"
            return result

        # Parse the output file
        result = _parse_perf_stat_output(output_file, target_pid, result.duration_seconds)

        # Calculate derived metrics
        if result.events:
            cycles = result.events.get("cycles", result.events.get("cpu-cycles", 0))
            instructions = result.events.get("instructions", 0)
            cache_misses = result.events.get("cache-misses", 0)
            cache_refs = result.events.get("cache-references", 1)  # Avoid div by zero

            if instructions > 0:
                result.cycles_per_instruction = cycles / instructions

            if cache_refs > 0:
                result.cache_miss_rate = (cache_misses / cache_refs) * 100

        logger.info(
            "Perf profiling complete: CPI=%.2f, Cache miss rate=%.2f%%",
            result.cycles_per_instruction or 0,
            result.cache_miss_rate or 0,
        )

        return result

    except subprocess.TimeoutExpired:
        result.error = "perf stat timed out"
        return result
    except Exception as e:
        result.error = f"Error running perf: {e}"
        return result


def _parse_perf_stat_output(
    output_file: str | Path,
    pid: int,
    duration: float,
) -> PerfResult:
    """Parse perf stat CSV output file.

    Args:
        output_file: Path to perf output file
        pid: Process ID that was profiled
        duration: Profiling duration

    Returns:
        Parsed PerfResult
    """
    result = PerfResult(pid=pid, duration_seconds=duration)
    events = {}
    output_path = Path(output_file)

    try:
        with output_path.open(encoding="utf-8") as f:
            content = f.read()

        result.raw_data = {"file_content": content}

        # Parse CSV format: counter,event,unit,etc.
        for line in content.strip().split("\n"):
            if line.startswith("#") or not line.strip():
                continue

            parts = line.split(",")
            if len(parts) >= 2:
                try:
                    counter = int(parts[0].strip())
                    event_name = parts[1].strip()
                    if event_name and counter >= 0:
                        events[event_name] = counter
                except ValueError, IndexError:
                    continue

        result.events = events
        return result

    except FileNotFoundError:
        result.error = f"Perf output file not found: {output_path}"
        return result
    except Exception as e:
        result.error = f"Error parsing perf output: {e}"
        return result


def run_perf_record(
    target_pid: int,
    config: PerfConfig | None = None,
) -> dict[str, Any]:
    """Run perf record to collect detailed sample data (for flame graphs).

    Args:
        target_pid: Process ID to profile
        config: Perf configuration

    Returns:
        Dictionary with perf record results and file paths
    """
    if config is None:
        config = PerfConfig()

    result: dict[str, Any] = {
        "success": False,
        "pid": target_pid,
        "perf_data_file": None,
        "perf_script_file": None,
        "error": None,
    }

    perf_path = _find_perf_binary()
    if not perf_path:
        result["error"] = "perf binary not found"
        return result

    # Check if we need sudo for perf
    perm_check = _check_perf_permissions(perf_path)
    needs_sudo = perm_check.get("needs_sudo", True)

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    data_file = output_dir / f"perf-record-{target_pid}-{timestamp}.data"

    extra_args = [
        "-p",
        str(target_pid),
        "-o",
        str(data_file),
        "--freq",
        str(config.sample_rate),
    ]
    if config.record_callgraph:
        extra_args.append("-g")
    extra_args.extend(["--", "sleep", str(config.duration)])

    cmd = _build_perf_cmd(perf_path, "record", needs_sudo, extra_args)

    logger.info("Starting perf record on PID %d for %d seconds", target_pid, config.duration)

    try:
        record_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.duration + 30,
        )

        if record_result.returncode != 0:
            result["error"] = f"perf record failed: {record_result.stderr}"
            return result

        result["success"] = True
        result["perf_data_file"] = str(data_file)

        # Generate perf script output (symbolic)
        script_file = data_file.with_suffix(".script")
        try:
            script_cmd = _build_perf_cmd(perf_path, "script", needs_sudo, ["-i", str(data_file)])
            script_result = subprocess.run(
                script_cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if script_result.returncode == 0:
                with script_file.open("w", encoding="utf-8") as f:
                    f.write(script_result.stdout)
                result["perf_script_file"] = str(script_file)
        except Exception as e:
            logger.warning("Failed to generate perf script: %s", e)

        return result

    except subprocess.TimeoutExpired:
        result["error"] = "perf record timed out"
        return result
    except Exception as e:
        result["error"] = f"Error running perf record: {e}"
        return result


def profile_mosquitto_container(
    container_name: str = "docker-mosquitto-1",
    config: PerfConfig | None = None,
) -> dict[str, Any]:
    """High-level function to profile the Mosquitto container.

        This is the main entry point for scenario integration. It discovers
    the container PID, finds the mosquitto process, and runs perf profiling.

        Args:
            container_name: Docker container name (default: docker-mosquitto-1)
            config: Perf configuration

        Returns:
            Dictionary with profiling results including PerfResult
    """
    if config is None:
        config = PerfConfig()

    result: dict[str, Any] = {
        "success": False,
        "container_name": container_name,
        "container_pid": None,
        "mosquitto_process": None,
        "perf_stat": None,
        "perf_record": None,
        "error": None,
    }

    # Check perf installation
    perf_check = check_perf_installation()
    if not perf_check["installed"]:
        result["error"] = f"perf not installed: {perf_check.get('error')}"
        return result

    # Get container PID
    container_pid = get_container_pid(container_name)
    if not container_pid:
        result["error"] = f"Could not find container {container_name}"
        return result

    result["container_pid"] = container_pid

    # Find mosquitto process
    mosquitto_info = find_mosquitto_process(container_pid)
    if not mosquitto_info:
        result["error"] = "Could not find mosquitto process in container"
        return result

    result["mosquitto_process"] = mosquitto_info
    target_pid = mosquitto_info["pid"]

    # Run perf stat
    logger.info("Profiling mosquitto (PID %d) for %d seconds", target_pid, config.duration)
    perf_stat_result = run_perf_stat(target_pid, config)
    result["perf_stat"] = perf_stat_result.__dict__

    # Optionally run perf record
    perf_record_result = run_perf_record(target_pid, config)
    result["perf_record"] = perf_record_result

    result["success"] = not bool(perf_stat_result.error)

    return result


def get_default_perf_scenarios() -> list[str]:
    """Get the list of scenarios recommended for perf profiling.

    Returns:
        List of scenario IDs that benefit from CPU profiling
    """
    return [
        "BASE-01",  # Baseline for comparison
        "JWT-01",  # JWT token verification cost
        "BIS-01",  # Biscuit token verification cost
        "POLICY-COMPLEX-1",  # Policy complexity baseline
        "POLICY-COMPLEX-5",  # Medium complexity
        "POLICY-COMPLEX-25",  # High block count
        "POLICY-COMPLEX-LOW",  # Datalog complexity low
        "POLICY-COMPLEX-MED",  # Datalog complexity medium
        "POLICY-COMPLEX-HIGH",  # Datalog complexity high
        "POLICY-AUTHZ-TEMPLATE-SIMPLE",  # Authorizer template baseline
        "POLICY-AUTHZ-TEMPLATE-RBAC",  # Authorizer template with role derivation
        "POLICY-AUTHZ-TEMPLATE-CONTEXTUAL",  # Authorizer template with contextual checks
        "THUNDERING-HERD",  # Connection burst CPU load
    ]


def format_perf_summary(perf_result: dict[str, Any]) -> str:
    """Format perf results for human-readable summary.

    Args:
        perf_result: Result from profile_mosquitto_container()

    Returns:
        Formatted summary string
    """
    if not perf_result.get("success"):
        return f"Perf profiling failed: {perf_result.get('error', 'Unknown error')}"

    stat = perf_result.get("perf_stat", {})
    if stat.get("error"):
        return f"Perf stat failed: {stat['error']}"

    events = stat.get("events", {})
    lines = [
        "=== CPU Performance Profile ===",
        f"Container: {perf_result['container_name']}",
        f"PID: {stat.get('pid')}",
        f"Duration: {stat.get('duration_seconds', 0):.1f}s",
        "",
        "Hardware Events:",
    ]

    for event, count in events.items():
        lines.append(f"  {event}: {count:,}")

    lines.extend(
        [
            "",
            "Derived Metrics:",
            f"  Cycles per Instruction (CPI): {stat.get('cycles_per_instruction', 0):.2f}",
            f"  Cache Miss Rate: {stat.get('cache_miss_rate', 0):.2f}%",
        ]
    )

    if perf_result.get("perf_record", {}).get("perf_data_file"):
        lines.append(f"\nPerf data saved: {perf_result['perf_record']['perf_data_file']}")

    return "\n".join(lines)
