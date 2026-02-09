"""Packet capture analysis module for pcap files.

Provides automated parsing and metrics extraction for TCP fragmentation analysis
during MTU stress tests using dpkt library.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dpkt


@dataclass
class StreamMetrics:
    """Metrics for a single TCP stream."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int = 0
    bytes: int = 0
    fragments: int = 0
    retransmissions: int = 0
    packet_times: list[float] = field(default_factory=list)

    @property
    def stream_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"


@dataclass
class PacketMetrics:
    """Overall packet capture metrics."""

    total_packets: int = 0
    total_bytes: int = 0
    fragment_count: int = 0
    retransmission_count: int = 0
    tcp_packets: int = 0
    ip_packets: int = 0
    packet_times: list[float] = field(default_factory=list)
    tcp_streams: dict[str, StreamMetrics] = field(default_factory=dict)


@dataclass
class FragmentationStats:
    """Fragmentation analysis results."""

    fragments_detected: int = 0
    fragmented_packets: int = 0
    max_fragment_chain: int = 0
    avg_fragment_size: float = 0.0
    min_fragment_size: int = 0
    max_fragment_size: int = 0
    token_size_bytes: int = 0
    expected_fragments: int = 0


# Estimated TCP/IP header overhead for fragmentation calculation.
# 20 bytes IPv4 header + 32 bytes TCP header (20 minimum + 12 bytes timestamps option).
# TCP timestamps (RFC 7323) are enabled by default on modern Linux systems.
HEADER_OVERHEAD_ESTIMATE = 52


@dataclass
class TokenSizeCorrelation:
    """Correlation between token size and fragmentation."""

    token_bytes: int = 0
    mtu_configured: int = 0
    fragmentation_ratio: float = 0.0
    bytes_per_fragment: float = 0.0
    packets_per_token_estimate: float = 0.0


def _ip_to_str(ip: bytes) -> str:
    """Convert IP address bytes to string."""
    return socket.inet_ntoa(ip)


def parse_pcap_with_dpkt(pcap_path: str | Path) -> PacketMetrics:
    """Parse pcap file using dpkt library for accurate binary parsing.

    Uses dpkt to read pcap files directly, avoiding text parsing fragility.
    Provides accurate IP header length detection and fragmentation analysis.

    Args:
        pcap_path: Path to pcap file

    Returns:
        PacketMetrics with parsed data

    Raises:
        FileNotFoundError: If pcap file does not exist
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"Pcap file not found: {pcap_path}")

    metrics = PacketMetrics()
    stream_map: dict[str, StreamMetrics] = {}
    # Track seen sequence numbers per stream to detect retransmissions
    seen_seqs: dict[str, set[str]] = {}

    with open(pcap_path, "rb") as f:
        reader = dpkt.pcap.Reader(f)

        for timestamp, buf in reader:
            metrics.total_packets += 1
            metrics.packet_times.append(timestamp)

            # Parse Ethernet frame
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.dpkt.NeedData:
                continue

            # Check for IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            metrics.ip_packets += 1

            # Get IP header length (actual bytes, not just 20)
            ip_header_len = ip.hl * 4

            # Check for TCP
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue

            tcp = ip.data
            metrics.tcp_packets += 1

            # Extract addresses and ports
            src_ip = _ip_to_str(ip.src)
            dst_ip = _ip_to_str(ip.dst)
            src_port = tcp.sport
            dst_port = tcp.dport

            # Create stream identifier
            stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

            if stream_key not in stream_map:
                stream_map[stream_key] = StreamMetrics(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                )
                seen_seqs[stream_key] = set()

            stream = stream_map[stream_key]
            stream.packets += 1
            stream.packet_times.append(timestamp)

            # Calculate packet length (IP total length - IP header + TCP data)
            pkt_len = ip.len - ip_header_len
            stream.bytes += pkt_len
            metrics.total_bytes += pkt_len

            # Detect fragmentation
            # More Fragments flag or non-zero fragment offset indicates fragmentation
            is_fragment = (ip.off & dpkt.ip.IP_MF) != 0 or (ip.off & dpkt.ip.IP_OFFMASK) != 0
            if is_fragment:
                stream.fragments += 1
                metrics.fragment_count += 1

            # Detect retransmissions
            seq_key = f"{tcp.seq}:{tcp.ack}"
            if seq_key in seen_seqs[stream_key]:
                stream.retransmissions += 1
                metrics.retransmission_count += 1
            else:
                seen_seqs[stream_key].add(seq_key)

    metrics.tcp_streams = stream_map
    return metrics


def count_fragments(metrics: PacketMetrics) -> int:
    """Get total fragment count from metrics."""
    return metrics.fragment_count


def count_retransmissions(metrics: PacketMetrics) -> int:
    """Get total retransmission count from metrics."""
    return metrics.retransmission_count


def calculate_inter_packet_deltas(metrics: PacketMetrics) -> dict[str, float]:
    """Calculate timing statistics between packets.

    Returns:
        Dict with p50, p95, p99, mean, max, min deltas in milliseconds
    """
    if len(metrics.packet_times) < 2:
        return {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "mean_ms": 0, "max_ms": 0, "min_ms": 0}

    times = sorted(metrics.packet_times)
    deltas = [(times[i + 1] - times[i]) * 1000 for i in range(len(times) - 1)]

    if not deltas:
        return {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "mean_ms": 0, "max_ms": 0, "min_ms": 0}

    deltas.sort()

    def percentile(data: list[float], p: float) -> float:
        k = (len(data) - 1) * p / 100
        f = int(k)
        c = f + 1 if f + 1 < len(data) else f
        return data[f] + (k - f) * (data[c] - data[f]) if c != f else data[f]

    return {
        "p50_ms": percentile(deltas, 50),
        "p95_ms": percentile(deltas, 95),
        "p99_ms": percentile(deltas, 99),
        "mean_ms": sum(deltas) / len(deltas),
        "max_ms": max(deltas),
        "min_ms": min(deltas),
    }


def analyze_fragmentation(
    metrics: PacketMetrics, mtu: int, token_len: int = 0
) -> FragmentationStats:
    """Analyze fragmentation statistics relative to MTU.

    Args:
        metrics: Packet capture metrics
        mtu: Configured MTU for the scenario
        token_len: Token size in bytes for correlation

    Returns:
        FragmentationStats with detailed analysis
    """
    stats = FragmentationStats(
        fragments_detected=metrics.fragment_count,
        token_size_bytes=token_len,
    )

    # Estimate expected fragments based on token size
    if token_len > 0 and mtu > 0:
        # Account for TCP/IP headers
        payload_per_packet = mtu - HEADER_OVERHEAD_ESTIMATE
        stats.expected_fragments = max(
            1, (token_len + payload_per_packet - 1) // payload_per_packet
        )

    # Calculate fragmented packets from streams
    fragmented_packets = 0
    max_chain = 0
    fragment_sizes: list[int] = []

    for stream in metrics.tcp_streams.values():
        if stream.fragments > 0:
            fragmented_packets += 1
            max_chain = max(max_chain, stream.fragments)
            # Estimate fragment sizes
            if stream.packets > 0:
                avg_size = stream.bytes // stream.packets
                fragment_sizes.extend([avg_size] * stream.fragments)

    stats.fragmented_packets = fragmented_packets
    stats.max_fragment_chain = max_chain

    if fragment_sizes:
        stats.avg_fragment_size = sum(fragment_sizes) / len(fragment_sizes)
        stats.min_fragment_size = min(fragment_sizes)
        stats.max_fragment_size = max(fragment_sizes)

    return stats


def correlate_with_token_size(
    metrics: PacketMetrics, token_len: int, mtu: int
) -> TokenSizeCorrelation:
    """Correlate token size with fragmentation behavior.

    Args:
        metrics: Packet capture metrics
        token_len: Token size in bytes
        mtu: Configured MTU

    Returns:
        TokenSizeCorrelation with ratio and estimate metrics
    """
    corr = TokenSizeCorrelation(
        token_bytes=token_len,
        mtu_configured=mtu,
    )

    if token_len > 0:
        corr.fragmentation_ratio = metrics.fragment_count / max(1, metrics.total_packets)
        corr.bytes_per_fragment = token_len / max(1, metrics.fragment_count)

        # Estimate packets per token based on typical token transmission patterns
        # CONNECT packet + potential reassembly overhead
        # 1.5x factor includes: TCP handshake overhead, MQTT CONNECT headers,
        # potential TLS record overhead if enabled, and reassembly margin
        if mtu > 0:
            packets_per_token = (token_len / mtu) * 1.5  # Include overhead factor
            corr.packets_per_token_estimate = max(1.0, packets_per_token)

    return corr


def parse_pcap(pcap_path: str | Path) -> PacketMetrics:
    """Parse pcap file using dpkt library.

    Args:
        pcap_path: Path to pcap file

    Returns:
        PacketMetrics with parsed data

    Raises:
        FileNotFoundError: If pcap file does not exist
        ImportError: If dpkt is not available
    """
    return parse_pcap_with_dpkt(pcap_path)


def analyze_pcap(
    pcap_path: str | Path,
    mtu: int = 1500,
    token_len: int = 0,
) -> dict[str, Any]:
    """Complete pcap analysis with all metrics.

    Args:
        pcap_path: Path to pcap file
        mtu: Configured MTU for the scenario
        token_len: Token size for correlation

    Returns:
        Dict with complete analysis results ready for JSON serialization
    """
    try:
        metrics = parse_pcap(pcap_path)
    except FileNotFoundError:
        return {
            "error": f"Pcap file not found: {pcap_path}",
            "pcap_file": str(pcap_path),
        }
    except Exception as e:
        return {
            "error": str(e),
            "pcap_file": str(pcap_path),
        }

    deltas = calculate_inter_packet_deltas(metrics)
    frag_stats = analyze_fragmentation(metrics, mtu, token_len)
    correlation = correlate_with_token_size(metrics, token_len, mtu)

    # Convert streams to serializable format
    streams_data = {}
    for stream_id, stream in metrics.tcp_streams.items():
        streams_data[stream_id] = {
            "src_ip": stream.src_ip,
            "src_port": stream.src_port,
            "dst_ip": stream.dst_ip,
            "dst_port": stream.dst_port,
            "packets": stream.packets,
            "bytes": stream.bytes,
            "fragments": stream.fragments,
            "retransmissions": stream.retransmissions,
        }

    return {
        "pcap_file": str(pcap_path),
        "metrics": {
            "total_packets": metrics.total_packets,
            "total_bytes": metrics.total_bytes,
            "fragment_count": metrics.fragment_count,
            "retransmission_count": metrics.retransmission_count,
            "tcp_packets": metrics.tcp_packets,
            "ip_packets": metrics.ip_packets,
        },
        "inter_packet_deltas_ms": deltas,
        "tcp_streams": streams_data,
        "fragmentation_stats": {
            "fragments_detected": frag_stats.fragments_detected,
            "fragmented_packets": frag_stats.fragmented_packets,
            "max_fragment_chain": frag_stats.max_fragment_chain,
            "avg_fragment_size": frag_stats.avg_fragment_size,
            "min_fragment_size": frag_stats.min_fragment_size,
            "max_fragment_size": frag_stats.max_fragment_size,
            "token_size_bytes": frag_stats.token_size_bytes,
            "expected_fragments": frag_stats.expected_fragments,
        },
        "token_size_correlation": {
            "token_bytes": correlation.token_bytes,
            "mtu_configured": correlation.mtu_configured,
            "fragmentation_ratio": correlation.fragmentation_ratio,
            "bytes_per_fragment": correlation.bytes_per_fragment,
            "packets_per_token_estimate": correlation.packets_per_token_estimate,
        },
    }


def check_pcap_parser_available() -> dict[str, Any]:
    """Check if dpkt pcap parser is available.

    Returns:
        Dict with installed status and version info
    """
    try:
        return {
            "installed": True,
            "parser": "dpkt",
            "version": dpkt.__version__ if hasattr(dpkt, "__version__") else "unknown",
        }
    except Exception:
        return {
            "installed": False,
            "parser": None,
            "error": "dpkt not available (install with: pip install dpkt)",
        }


def format_packet_summary(analysis: dict[str, Any]) -> str:
    """Format analysis results as a human-readable summary.

    Args:
        analysis: Analysis dict from analyze_pcap()

    Returns:
        Formatted summary string
    """
    if "error" in analysis:
        return f"Packet analysis failed: {analysis['error']}"

    metrics = analysis.get("metrics", {})
    frag_stats = analysis.get("fragmentation_stats", {})
    correlation = analysis.get("token_size_correlation", {})
    deltas = analysis.get("inter_packet_deltas_ms", {})

    lines = [
        "Packet Capture Analysis Summary",
        "=" * 40,
        f"Total packets: {metrics.get('total_packets', 0)}",
        f"Total bytes: {metrics.get('total_bytes', 0)}",
        f"Fragment count: {metrics.get('fragment_count', 0)}",
        f"Retransmissions: {metrics.get('retransmission_count', 0)}",
        "",
        "Inter-packet timing (ms):",
        f"  p50: {deltas.get('p50_ms', 0):.3f}",
        f"  p95: {deltas.get('p95_ms', 0):.3f}",
        f"  p99: {deltas.get('p99_ms', 0):.3f}",
        "",
        "Fragmentation analysis:",
        f"  Fragments detected: {frag_stats.get('fragments_detected', 0)}",
        f"  Fragmented packets: {frag_stats.get('fragmented_packets', 0)}",
        f"  Max fragment chain: {frag_stats.get('max_fragment_chain', 0)}",
        f"  Avg fragment size: {frag_stats.get('avg_fragment_size', 0):.1f}",
        "",
        "Token size correlation:",
        f"  Token bytes: {correlation.get('token_bytes', 0)}",
        f"  MTU configured: {correlation.get('mtu_configured', 0)}",
        f"  Fragmentation ratio: {correlation.get('fragmentation_ratio', 0):.4f}",
    ]

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python packet_analysis.py <pcap_file> [mtu] [token_len]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    mtu = int(sys.argv[2]) if len(sys.argv) > 2 else 1500
    token_len = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    # Check parser availability
    avail = check_pcap_parser_available()
    if not avail["installed"]:
        print(f"Error: {avail['error']}")
        sys.exit(1)

    print(f"Analyzing {pcap_file}...")
    result = analyze_pcap(pcap_file, mtu, token_len)
    print(format_packet_summary(result))

    # Also output JSON
    print("\nJSON output:")
    print(json.dumps(result, indent=2))
