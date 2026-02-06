"""iperf3 baseline measurement for network capacity testing.

This module provides functionality to measure network baseline capacity
using iperf3, which is essential for interpreting throughput results
in MQTT benchmark scenarios.
"""

import json
import subprocess
import time
from typing import Any

from benchmarks.logging_utils import get_logger

logger = get_logger(__name__)

DEFAULT_IPERF3_HOST = "localhost"
DEFAULT_IPERF3_PORT = 5201
DEFAULT_DURATION_SECONDS = 10
DEFAULT_PARALLEL_STREAMS = 4


def run_iperf3_baseline(
    host: str = DEFAULT_IPERF3_HOST,
    port: int = DEFAULT_IPERF3_PORT,
    duration: int = DEFAULT_DURATION_SECONDS,
    parallel_streams: int = DEFAULT_PARALLEL_STREAMS,
    tcp_window_size: str | None = None,
    reverse_mode: bool = True,  # Server sends, client receives (measures download)
) -> dict[str, Any]:
    """Run iperf3 test to measure network baseline capacity.

    Args:
        host: iperf3 server hostname
        port: iperf3 server port
        duration: Test duration in seconds
        parallel_streams: Number of parallel streams
        tcp_window_size: TCP window size (e.g., "256K")
        reverse_mode: If True, measure download (server->client), else upload

    Returns:
        Dictionary containing iperf3 results and parsed metrics
    """
    cmd = [
        "iperf3",
        "-c",
        host,
        "-p",
        str(port),
        "-t",
        str(duration),
        "-P",
        str(parallel_streams),
        "-J",  # JSON output
    ]

    if reverse_mode:
        cmd.append("-R")  # Reverse mode: server sends, client receives

    if tcp_window_size:
        cmd.extend(["-w", tcp_window_size])

    logger.info(
        "Running iperf3 baseline: %s streams, %ss duration, reverse=%s",
        parallel_streams,
        duration,
        reverse_mode,
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 30,  # Extra time for setup/teardown
        )

        if result.returncode != 0:
            logger.error("iperf3 failed with return code %d: %s", result.returncode, result.stderr)
            return {
                "error": f"iperf3 failed: {result.stderr}",
                "return_code": result.returncode,
                "host": host,
                "port": port,
                "duration_requested": duration,
            }

        # Parse JSON output
        iperf_data = json.loads(result.stdout)
        return _parse_iperf3_results(iperf_data, host, port, duration)

    except subprocess.TimeoutExpired:
        logger.error("iperf3 timed out after %s seconds", duration + 30)
        return {
            "error": "iperf3 timeout",
            "host": host,
            "port": port,
            "duration_requested": duration,
        }
    except json.JSONDecodeError as e:
        logger.error("Failed to parse iperf3 JSON output: %s", e)
        return {
            "error": f"JSON parse error: {e}",
            "raw_output": result.stdout if "result" in dir() else None,
            "host": host,
            "port": port,
        }
    except FileNotFoundError:
        logger.error("iperf3 not found in PATH")
        return {
            "error": "iperf3 not installed",
            "host": host,
            "port": port,
        }
    except Exception as e:
        logger.error("Unexpected error running iperf3: %s", e)
        return {
            "error": str(e),
            "host": host,
            "port": port,
        }


def _parse_iperf3_results(iperf_data: dict, host: str, port: int, duration: int) -> dict[str, Any]:
    """Parse iperf3 JSON output into structured metrics.

    Args:
        iperf_data: Parsed iperf3 JSON output
        host: Server host
        port: Server port
        duration: Requested duration

    Returns:
        Dictionary with extracted metrics
    """
    try:
        # Extract end summary - use sender/receiver depending on reverse mode
        end = iperf_data.get("end", {})

        # In reverse mode (-R), sender is server, receiver is client (what we measure)
        # In normal mode, sender is client (upload), receiver is server
        sender = end.get("sum_sent", {})
        receiver = end.get("sum_received", {})

        # Determine which direction we're measuring
        # With -R (reverse), we're interested in received bytes (download)
        measured = receiver if end.get("sum_received") else sender

        # Calculate key metrics
        bits_per_second = measured.get("bits_per_second", 0)
        bytes_transferred = measured.get("bytes", 0)
        bytes_per_second = bits_per_second / 8

        # Jitter and packet loss for UDP (if applicable)
        jitter_ms = 0.0
        lost_packets = 0
        total_packets = 0
        loss_percent = 0.0

        if "streams" in end and end["streams"]:
            udp_info = end["streams"][0].get("udp", {})
            jitter_ms = udp_info.get("jitter_ms", 0.0)
            lost_packets = udp_info.get("lost_packets", 0)
            total_packets = udp_info.get("packets", 0)
            if total_packets > 0:
                loss_percent = (lost_packets / total_packets) * 100

        # TCP retransmits (TCP mode)
        retransmits = 0
        if "streams" in end and end["streams"]:
            sender_info = end["streams"][0].get("sender", {})
            retransmits = sender_info.get("retransmits", 0)

        # RTT information
        rtt_ms = None
        if "streams" in end and end["streams"]:
            stream = end["streams"][0]
            if "sender" in stream:
                rtt_ms = stream["sender"].get("mean_rtt", 0) / 1000.0  # Convert us to ms

        result = {
            "host": host,
            "port": port,
            "duration_requested": duration,
            "duration_actual": measured.get("seconds", duration),
            "throughput": {
                "bits_per_second": bits_per_second,
                "bytes_per_second": bytes_per_second,
                "megabits_per_second": bits_per_second / 1_000_000,
                "megabytes_per_second": bytes_per_second / 1_000_000,
            },
            "bytes_transferred": bytes_transferred,
            "packets": {
                "total": total_packets,
                "lost": lost_packets,
                "loss_percent": loss_percent,
            },
            "tcp": {
                "retransmits": retransmits,
                "rtt_ms": rtt_ms,
            },
            "udp": {
                "jitter_ms": jitter_ms,
            },
            "raw_summary": {
                "sender": sender,
                "receiver": receiver,
            },
        }

        logger.info(
            "iperf3 baseline complete: %.2f Mbps, %.2f ms RTT",
            result["throughput"]["megabits_per_second"],
            rtt_ms or 0,
        )

        return result

    except Exception as e:
        logger.error("Error parsing iperf3 results: %s", e)
        return {
            "error": f"Parse error: {e}",
            "raw_data": iperf_data,
            "host": host,
            "port": port,
        }


def check_network_validity(
    baseline_result: dict[str, Any],
    expected_min_mbps: float = 100.0,
    expected_max_loss_percent: float = 1.0,
) -> dict[str, Any]:
    """Check if network capacity is sufficient for valid test results.

    Args:
        baseline_result: Result from run_iperf3_baseline()
        expected_min_mbps: Minimum expected throughput in Mbps
        expected_max_loss_percent: Maximum acceptable packet loss %

    Returns:
        Dictionary with validity assessment
    """
    if "error" in baseline_result:
        return {
            "valid": False,
            "reason": baseline_result["error"],
            "baseline": baseline_result,
        }

    throughput_mbps = baseline_result.get("throughput", {}).get("megabits_per_second", 0)
    loss_percent = baseline_result.get("packets", {}).get("loss_percent", 0)

    checks = {
        "throughput_sufficient": throughput_mbps >= expected_min_mbps,
        "loss_acceptable": loss_percent <= expected_max_loss_percent,
    }

    all_passed = all(checks.values())

    assessment: dict[str, Any] = {
        "valid": all_passed,
        "checks": checks,
        "metrics": {
            "throughput_mbps": throughput_mbps,
            "loss_percent": loss_percent,
            "expected_min_mbps": expected_min_mbps,
            "expected_max_loss_percent": expected_max_loss_percent,
        },
        "warnings": [],
    }

    if not checks["throughput_sufficient"]:
        assessment["warnings"].append(
            f"Network throughput ({throughput_mbps:.2f} Mbps) below expected "
            f"minimum ({expected_min_mbps:.2f} Mbps). Results may not reflect "
            f"true system performance."
        )

    if not checks["loss_acceptable"]:
        assessment["warnings"].append(
            f"Packet loss ({loss_percent:.2f}%) exceeds acceptable threshold "
            f"({expected_max_loss_percent:.2f}%). Results may be unreliable."
        )

    return assessment


def run_baseline_with_retry(
    host: str = DEFAULT_IPERF3_HOST,
    port: int = DEFAULT_IPERF3_PORT,
    duration: int = DEFAULT_DURATION_SECONDS,
    retries: int = 2,
    **kwargs,
) -> dict[str, Any]:
    """Run iperf3 baseline with automatic retry on failure.

    Args:
        host: iperf3 server hostname
        port: iperf3 server port
        duration: Test duration in seconds
        retries: Number of retry attempts
        **kwargs: Additional arguments passed to run_iperf3_baseline()

    Returns:
        Best available result (successful or last attempt)
    """
    last_result = None

    for attempt in range(retries + 1):
        if attempt > 0:
            logger.info("iperf3 retry attempt %d/%d", attempt, retries)
            time.sleep(2)  # Brief delay before retry

        result = run_iperf3_baseline(host=host, port=port, duration=duration, **kwargs)

        last_result = result

        if "error" not in result:
            result["attempts"] = attempt + 1
            return result

    # All attempts failed
    if last_result is None:
        return {"error": "All attempts failed", "attempts": retries + 1}
    last_result["attempts"] = retries + 1
    last_result["all_attempts_failed"] = True
    return last_result
