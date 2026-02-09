#!/bin/sh
set -eu

IFACE="${TCPDUMP_IFACE:-eth0}"
FILTER="${TCPDUMP_FILTER:-port 1883 or port 8883}"
DURATION="${TCPDUMP_DURATION:-300}"
OUTPUT="${TCPDUMP_OUTPUT:-/pcap/capture.pcap}"

# Wait for interface to be ready
sleep 2

# Check if interface exists
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "Warning: Interface $IFACE not found, trying to detect..."
    IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
    echo "Using interface: $IFACE"
fi

echo "Starting tcpdump on $IFACE with filter: $FILTER"
echo "Output: $OUTPUT"
echo "Duration: ${DURATION}s (or until signal)"

# Run tcpdump with timeout
# Note: $FILTER is intentionally unquoted to allow compound filter expressions like "port 1883 or port 8883"
timeout "$DURATION" tcpdump -i "$IFACE" -w "$OUTPUT" $FILTER 2>&1 || true

echo "Capture complete: $OUTPUT"
ls -la "$OUTPUT" 2>/dev/null || echo "No pcap file created"

# Keep container running if requested
if [ "${TCPDUMP_KEEP_ALIVE:-0}" = "1" ]; then
    tail -f /dev/null
fi
