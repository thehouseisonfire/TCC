import base64
import json
import socket
import ssl
import time

import typer

from benchmarks.logging_utils import get_logger, setup_logging


def _enc_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        digit = n % 128
        n //= 128
        if n > 0:
            digit |= 0x80
        out.append(digit)
        if n == 0:
            break
    return bytes(out)


def _enc_u16(n: int) -> bytes:
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def _enc_utf8(s: str) -> bytes:
    b = s.encode("utf-8")
    return _enc_u16(len(b)) + b


def _enc_bin(b: bytes) -> bytes:
    return _enc_u16(len(b)) + b


def _dec_varint(buf: bytes, offset: int = 0):
    multiplier = 1
    value = 0
    i = 0
    while True:
        digit = buf[offset + i]
        value += (digit & 127) * multiplier
        multiplier *= 128
        i += 1
        if (digit & 128) == 0:
            break
        if i > 4:
            raise ValueError("varint too long")
    return value, i


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise ConnectionError("socket closed")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _recv_packet(sock: socket.socket):
    fh = _recv_exact(sock, 1)
    first = fh[0]
    rl_bytes = bytearray()
    while True:
        b = _recv_exact(sock, 1)[0]
        rl_bytes.append(b)
        if (b & 0x80) == 0:
            break
        if len(rl_bytes) > 4:
            raise ValueError("remaining length too long")
    remaining_len, _ = _dec_varint(bytes(rl_bytes), 0)
    payload = _recv_exact(sock, remaining_len)
    return first >> 4, payload


def _props_auth(method: str, data: bytes) -> bytes:
    props = bytearray()
    props.append(0x15)
    props += _enc_utf8(method)
    props.append(0x16)
    props += _enc_bin(data)
    return _enc_varint(len(props)) + props


def _build_connect(
    client_id: str, auth_method: str, auth_data: bytes, keepalive: int = 60
) -> bytes:
    vh = bytearray()
    vh += _enc_utf8("MQTT")
    vh.append(5)
    connect_flags = 0b00000010
    vh.append(connect_flags)
    vh += _enc_u16(keepalive)
    vh += _props_auth(auth_method, auth_data)

    pl = bytearray()
    pl += _enc_utf8(client_id)

    remaining = bytes(vh) + bytes(pl)
    fixed = bytes([0x10]) + _enc_varint(len(remaining))
    return fixed + remaining


def _build_auth(reason_code: int, auth_method: str, auth_data: bytes) -> bytes:
    vh = bytearray()
    vh.append(reason_code)
    vh += _props_auth(auth_method, auth_data)
    fixed = bytes([0xF0]) + _enc_varint(len(vh))
    return fixed + bytes(vh)


def _build_disconnect(reason_code: int = 0) -> bytes:
    vh = bytes([reason_code]) + _enc_varint(0)
    fixed = bytes([0xE0]) + _enc_varint(len(vh))
    return fixed + vh


logger = get_logger(__name__)
app = typer.Typer(add_completion=False)


@app.command()
def main(
    host: str = "localhost",
    port: int = 1883,
    client_id: str = "client_auth",
    auth_method: str = "token",
    token1: str = typer.Option(..., "--token1"),
    token2: str = typer.Option(..., "--token2"),
    binary_mode: bool = typer.Option(
        False, "--binary/--text", help="Use binary Protobuf format (Biscuit only)"
    ),
    sleep: float = 2.0,
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_insecure: bool = False,
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)

    # Prepare auth data: binary mode decodes base64 to raw bytes
    if binary_mode:
        try:
            auth_data1 = base64.urlsafe_b64decode(token1 + "==")  # Add padding if needed
            auth_data2 = base64.urlsafe_b64decode(token2 + "==")
        except Exception as e:
            logger.error(f"Failed to decode binary token: {e}")
            raise typer.Exit(1) from e
    else:
        # Text mode (default): encode string as UTF-8
        auth_data1 = token1.encode("utf-8")
        auth_data2 = token2.encode("utf-8")

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(10)
    sock: socket.socket = raw_sock
    if tls:
        ctx = ssl.create_default_context(cafile=tls_ca_file)
        if tls_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)

    t0 = time.perf_counter()
    sock.connect((host, port))
    sock.sendall(_build_connect(client_id, auth_method, auth_data1))

    pkt_type, payload = _recv_packet(sock)
    t1 = time.perf_counter()

    ok = False
    reason = None
    if pkt_type == 2 and len(payload) >= 2 and len(payload) >= 3:
        reason = payload[1]
        ok = reason == 0

    connect_ms = (t1 - t0) * 1000.0

    time.sleep(sleep)

    t2 = time.perf_counter()
    sock.sendall(_build_auth(0x19, auth_method, auth_data2))

    pkt_type2, payload2 = _recv_packet(sock)
    t3 = time.perf_counter()

    reauth_ms = (t3 - t2) * 1000.0

    sock.sendall(_build_disconnect(0))
    sock.close()

    out = {
        "connect_ms": connect_ms,
        "connect_pkt_type": pkt_type,
        "connect_reason": reason,
        "connect_ok": ok,
        "reauth_ms": reauth_ms,
        "reauth_pkt_type": pkt_type2,
        "reauth_payload_len": len(payload2),
        "binary_mode": binary_mode,
        "token1_bytes": len(auth_data1),
        "token2_bytes": len(auth_data2),
    }

    typer.echo(json.dumps(out, indent=2))


if __name__ == "__main__":
    app()
