#!/bin/sh
set -eu

IFACE="${NETEM_IFACE:-eth0}"

if [ "${NETEM_MTU:-}" != "" ]; then
  ip link set dev "$IFACE" mtu "$NETEM_MTU"
fi

if [ "${NETEM_CLEAR:-0}" = "1" ]; then
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
fi

DELAY_MS="${NETEM_DELAY_MS:-}"
LOSS_PCT="${NETEM_LOSS_PCT:-}"
RATE_KBIT="${NETEM_RATE_KBIT:-}"

if [ "$DELAY_MS" != "" ] || [ "$LOSS_PCT" != "" ]; then
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  ARGS=""
  if [ "$DELAY_MS" != "" ]; then
    ARGS="$ARGS delay ${DELAY_MS}ms"
  fi
  if [ "$LOSS_PCT" != "" ]; then
    ARGS="$ARGS loss ${LOSS_PCT}%"
  fi
  tc qdisc add dev "$IFACE" root netem $ARGS
fi

if [ "$RATE_KBIT" != "" ]; then
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  tc qdisc add dev "$IFACE" root tbf rate ${RATE_KBIT}kbit burst 32kbit latency 400ms
fi

exec tail -f /dev/null
