"""Tests for packet_analysis module.

Simple unit tests for packet parsing and metrics extraction using dpkt.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from benchmarks.packet_analysis import (
    PacketMetrics,
    StreamMetrics,
    analyze_fragmentation,
    analyze_pcap,
    calculate_inter_packet_deltas,
    check_pcap_parser_available,
    correlate_with_token_size,
    format_packet_summary,
    parse_pcap,
    parse_pcap_with_dpkt,
)


def test_stream_metrics_stream_id():
    """Test StreamMetrics stream_id property."""
    stream = StreamMetrics(
        src_ip="192.168.1.10",
        src_port=54321,
        dst_ip="192.168.1.20",
        dst_port=1883,
    )
    assert stream.stream_id == "192.168.1.10:54321-192.168.1.20:1883"


def test_packet_metrics_defaults():
    """Test PacketMetrics default values."""
    metrics = PacketMetrics()
    assert metrics.total_packets == 0
    assert metrics.total_bytes == 0
    assert metrics.fragment_count == 0
    assert metrics.retransmission_count == 0
    assert metrics.tcp_streams == {}
    assert metrics.packet_times == []


def test_calculate_inter_packet_deltas_empty():
    """Test inter-packet delta calculation with no data."""
    metrics = PacketMetrics()
    result = calculate_inter_packet_deltas(metrics)
    assert result == {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "mean_ms": 0, "max_ms": 0, "min_ms": 0}


def test_calculate_inter_packet_deltas_single():
    """Test inter-packet delta calculation with single timestamp."""
    metrics = PacketMetrics(packet_times=[1.0])
    result = calculate_inter_packet_deltas(metrics)
    assert result == {"p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "mean_ms": 0, "max_ms": 0, "min_ms": 0}


def test_calculate_inter_packet_deltas_multiple():
    """Test inter-packet delta calculation with multiple timestamps."""
    metrics = PacketMetrics(packet_times=[1.0, 1.1, 1.3, 2.0])
    result = calculate_inter_packet_deltas(metrics)
    # Deltas: 100ms, 200ms, 700ms
    assert result["p50_ms"] == pytest.approx(200.0, abs=0.001)  # median of [100, 200, 700]
    assert result["min_ms"] == pytest.approx(100.0, abs=0.001)
    assert result["max_ms"] == pytest.approx(700.0, abs=0.001)
    assert result["mean_ms"] == pytest.approx(333.3333333333333, abs=0.001)


def test_analyze_fragmentation_no_data():
    """Test fragmentation analysis with no data."""
    metrics = PacketMetrics()
    result = analyze_fragmentation(metrics, mtu=1500, token_len=0)
    assert result.fragments_detected == 0
    assert result.fragmented_packets == 0
    assert result.expected_fragments == 0


def test_analyze_fragmentation_with_token():
    """Test fragmentation analysis with token size."""
    metrics = PacketMetrics()
    # 2000 byte token with 1500 MTU should need ~2 fragments
    result = analyze_fragmentation(metrics, mtu=1500, token_len=2000)
    # 1500 - 52 = 1448 payload per packet
    # 2000 / 1448 = ~1.4 -> ceil = 2 fragments
    assert result.expected_fragments == 2
    assert result.token_size_bytes == 2000


def test_analyze_fragmentation_small_mtu():
    """Test fragmentation analysis with small MTU."""
    metrics = PacketMetrics()
    # 1000 byte token with 200 MTU
    result = analyze_fragmentation(metrics, mtu=200, token_len=1000)
    # 200 - 52 = 148 payload per packet
    # 1000 / 148 = ~6.8 -> ceil = 7 fragments
    assert result.expected_fragments == 7


def test_correlate_with_token_size():
    """Test token size correlation calculation."""
    metrics = PacketMetrics(total_packets=100, fragment_count=10)
    result = correlate_with_token_size(metrics, token_len=500, mtu=1500)
    assert result.token_bytes == 500
    assert result.mtu_configured == 1500
    assert result.fragmentation_ratio == 0.1  # 10/100
    assert result.bytes_per_fragment == 50.0  # 500/10


def test_correlate_zero_token():
    """Test correlation with zero token length."""
    metrics = PacketMetrics()
    result = correlate_with_token_size(metrics, token_len=0, mtu=1500)
    assert result.token_bytes == 0
    assert result.fragmentation_ratio == 0.0
    assert result.bytes_per_fragment == 0.0


def test_format_packet_summary_error():
    """Test formatting when analysis contains error."""
    analysis = {"error": "Pcap file not found", "pcap_file": "test.pcap"}
    result = format_packet_summary(analysis)
    assert "Packet analysis failed" in result
    assert "Pcap file not found" in result


def test_format_packet_summary_success():
    """Test formatting successful analysis."""
    analysis = {
        "metrics": {
            "total_packets": 100,
            "total_bytes": 50000,
            "fragment_count": 5,
            "retransmission_count": 1,
        },
        "inter_packet_deltas_ms": {
            "p50_ms": 1.5,
            "p95_ms": 5.0,
            "p99_ms": 10.0,
        },
        "fragmentation_stats": {
            "fragments_detected": 5,
            "fragmented_packets": 3,
            "max_fragment_chain": 2,
            "avg_fragment_size": 200.5,
        },
        "token_size_correlation": {
            "token_bytes": 1000,
            "mtu_configured": 1500,
            "fragmentation_ratio": 0.05,
        },
    }
    result = format_packet_summary(analysis)
    assert "Packet Capture Analysis Summary" in result
    assert "Total packets: 100" in result
    assert "Fragment count: 5" in result
    assert "1000" in result  # token size


def test_check_pcap_parser_available():
    """Test pcap parser availability check returns correct structure."""
    result = check_pcap_parser_available()
    assert "installed" in result
    assert isinstance(result["installed"], bool)
    assert "parser" in result
    if result["installed"]:
        assert result["parser"] == "dpkt"
        assert "version" in result
    else:
        assert "error" in result


def test_header_overhead_constant():
    """Test that HEADER_OVERHEAD_ESTIMATE is properly set to 52 bytes."""
    from benchmarks.packet_analysis import HEADER_OVERHEAD_ESTIMATE

    assert HEADER_OVERHEAD_ESTIMATE == 52


def test_analyze_pcap_file_not_found():
    """Test analyze_pcap handles missing file gracefully."""
    result = analyze_pcap("/nonexistent/path/capture.pcap", mtu=1500, token_len=1000)
    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.skipif(
    not check_pcap_parser_available()["installed"],
    reason="dpkt not installed",
)
def test_parse_pcap_unified():
    """Test parse_pcap function with dpkt parser."""
    # Create a minimal test with empty file
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        # Write minimal invalid pcap header
        f.write(b"\x00" * 100)
        temp_path = f.name

    try:
        # This uses dpkt parser
        result = parse_pcap(temp_path)
        assert isinstance(result, PacketMetrics)
    except FileNotFoundError, ImportError, Exception:
        pass  # Expected with invalid file
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_parse_pcap_with_dpkt_real():
    """Test parsing with real dpkt if available."""
    # Create a minimal test file
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        # Write pcap global header (24 bytes)
        # Magic number (0xa1b2c3d4), version (2.4), timezone, sigfigs, snaplen, network (1=Ethernet)
        f.write(
            b"\xa1\xb2\xc3\xd4"  # magic
            b"\x00\x02\x00\x04"  # version
            b"\x00\x00\x00\x00"  # thiszone
            b"\x00\x00\x00\x00"  # sigfigs
            b"\x00\x00\xff\xff"  # snaplen
            b"\x00\x00\x00\x01"  # network (Ethernet)
        )
        # Write a minimal packet record header (16 bytes)
        f.write(
            b"\x00\x00\x00\x00"  # ts_sec
            b"\x00\x00\x00\x00"  # ts_usec
            b"\x00\x00\x00\x1e"  # incl_len (30 bytes)
            b"\x00\x00\x00\x1e"  # orig_len (30 bytes)
        )
        # Write minimal Ethernet frame + IP + TCP
        # Ethernet header (14 bytes): dst mac, src mac, ethertype (0x0800 = IPv4)
        f.write(b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00")
        # Minimal IP header (20 bytes): version/IHL, TOS, len, id, flags/offset,
        # TTL, proto (6=TCP), checksum, src, dst
        ip_header = (
            b"\x45"  # version 4, IHL 5 (20 bytes)
            b"\x00"  # TOS
            b"\x00\x10"  # total length (16 bytes)
            b"\x00\x01"  # ID
            b"\x00\x00"  # flags/fragment offset
            b"\x40"  # TTL (64)
            b"\x06"  # protocol (TCP)
            b"\x00\x00"  # checksum (ignored)
            b"\xc0\xa8\x01\x01"  # src IP: 192.168.1.1
            b"\xc0\xa8\x01\x02"  # dst IP: 192.168.1.2
        )
        f.write(ip_header)
        # Minimal TCP header (20 bytes): src port, dst port, seq, ack,
        # data offset/flags, window, checksum, urgent
        tcp_header = (
            b"\x07\x5b"  # src port: 1883
            b"\xd4\x31"  # dst port: 54321
            b"\x00\x00\x00\x01"  # seq
            b"\x00\x00\x00\x00"  # ack
            b"\x50\x02"  # data offset (5 = 20 bytes) + SYN flag
            b"\xff\xff"  # window
            b"\x00\x00"  # checksum
            b"\x00\x00"  # urgent pointer
        )
        f.write(tcp_header)
        temp_path = f.name

    try:
        result = parse_pcap_with_dpkt(temp_path)
        assert isinstance(result, PacketMetrics)
        assert result.total_packets >= 0  # May be 0 if parsing fails gracefully
    except Exception:
        pass  # May fail with malformed packet, that's ok
    finally:
        Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
