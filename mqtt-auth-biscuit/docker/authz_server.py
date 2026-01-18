import json
import os
import random
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return int(v)


def _env_float(name: str, default: float) -> float:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return float(v)


class State:
    def __init__(self) -> None:
        self.delay_ms = _env_int("AUTHZ_DELAY_MS", 0)
        self.fail_mode = os.environ.get("AUTHZ_FAIL_MODE", "none")
        self.fail_rate = _env_float("AUTHZ_FAIL_RATE", 0.0)
        self.allow_mode = os.environ.get("AUTHZ_ALLOW_MODE", "topic_prefix")
        self.topic_prefix = os.environ.get("AUTHZ_TOPIC_PREFIX", "sensors/")


STATE = State()


class Handler(BaseHTTPRequestHandler):
    server_version = "authz/0.1"

    def _send_json(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self._send_json(200, {"ok": True})
        return self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/config":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length > 0 else b"{}"
                req = json.loads(body.decode("utf-8"))

                if "delay_ms" in req:
                    STATE.delay_ms = int(req["delay_ms"])
                if "fail_mode" in req:
                    STATE.fail_mode = str(req["fail_mode"])
                if "fail_rate" in req:
                    STATE.fail_rate = float(req["fail_rate"])
                if "allow_mode" in req:
                    STATE.allow_mode = str(req["allow_mode"])
                if "topic_prefix" in req:
                    STATE.topic_prefix = str(req["topic_prefix"])

                return self._send_json(
                    200,
                    {
                        "ok": True,
                        "delay_ms": STATE.delay_ms,
                        "fail_mode": STATE.fail_mode,
                        "fail_rate": STATE.fail_rate,
                        "allow_mode": STATE.allow_mode,
                        "topic_prefix": STATE.topic_prefix,
                    },
                )
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        if self.path != "/authorize":
            return self._send_json(404, {"error": "not found"})

        if STATE.delay_ms > 0:
            time.sleep(STATE.delay_ms / 1000.0)

        if STATE.fail_mode == "always":
            return self._send_json(503, {"allow": False, "error": "forced failure"})
        if STATE.fail_mode == "rate":
            if random.random() < max(0.0, min(1.0, STATE.fail_rate)):
                return self._send_json(503, {"allow": False, "error": "random failure"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            req = json.loads(body.decode("utf-8"))
        except Exception:
            req = {}

        topic = str(req.get("topic", ""))

        if STATE.allow_mode == "allow_all":
            allowed = True
        elif STATE.allow_mode == "deny_all":
            allowed = False
        else:
            allowed = topic.startswith(STATE.topic_prefix)

        return self._send_json(200, {"allow": allowed})

    def log_message(self, fmt, *args):
        if os.environ.get("AUTHZ_LOG", "0") == "1":
            super().log_message(fmt, *args)


def main() -> None:
    host = os.environ.get("AUTHZ_HOST", "0.0.0.0")
    port = int(os.environ.get("AUTHZ_PORT", "8081"))
    tls_enabled = os.environ.get("AUTHZ_TLS", "0") in {"1", "true", "TRUE"}
    tls_cert = os.environ.get("AUTHZ_TLS_CERT")
    tls_key = os.environ.get("AUTHZ_TLS_KEY")
    httpd = HTTPServer((host, port), Handler)
    if tls_enabled:
        if not tls_cert or not tls_key:
            raise SystemExit("AUTHZ_TLS_CERT and AUTHZ_TLS_KEY must be set when AUTHZ_TLS=1")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
