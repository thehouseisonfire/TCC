#!/bin/sh
set -eu

if [ -n "${LOADGEN_MTU:-}" ]; then
  iface="${LOADGEN_IFACE:-eth0}"
  ip link set dev "$iface" mtu "$LOADGEN_MTU"
  ethtool -K "$iface" tso off gso off gro off
fi

exec /usr/local/bin/mqtt-loadgen "$@"
