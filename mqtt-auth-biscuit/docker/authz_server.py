import json
import os
import random
import time
import sys
import asyncio
from http import HTTPStatus

# Hypercorn is required for HTTP/2 support
from hypercorn.config import Config
from hypercorn.asyncio import serve

from logging_utils import get_logger, setup_logging

BENCHMARKS_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmarks")
if BENCHMARKS_DIR not in sys.path:
    sys.path.append(BENCHMARKS_DIR)

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

logger = get_logger(__name__)
STATE = State()

# Helper to format WSGI response
def send_json(start_response, code: int, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    status_text = HTTPStatus(code).phrase
    status = f"{code} {status_text}"
    response_headers = [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(data)))
    ]
    start_response(status, response_headers)
    return [data]

# The blocking WSGI Application
def application(environ, start_response):
    path = environ.get('PATH_INFO', '')
    method = environ.get('REQUEST_METHOD', 'GET')
    
    # --- GET Handling ---
    if method == "GET":
        if path == "/health":
            return send_json(start_response, 200, {"ok": True})
        return send_json(start_response, 404, {"error": "not found"})

    # --- POST Handling ---
    elif method == "POST":
        if path == "/config":
            try:
                # Read Content-Length
                try:
                    length = int(environ.get('CONTENT_LENGTH', 0))
                except (ValueError, TypeError):
                    length = 0
                
                # Blocking read from wsgi.input
                body = environ['wsgi.input'].read(length) if length > 0 else b"{}"
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

                return send_json(start_response, 200, {
                    "ok": True,
                    "delay_ms": STATE.delay_ms,
                    "fail_mode": STATE.fail_mode,
                    "fail_rate": STATE.fail_rate,
                    "allow_mode": STATE.allow_mode,
                    "topic_prefix": STATE.topic_prefix,
                })
            except Exception as e:
                return send_json(start_response, 400, {"ok": False, "error": str(e)})

        if path != "/authorize":
            return send_json(start_response, 404, {"error": "not found"})

        # Blocking logic (Benchmarks rely on this actually blocking the worker)
        if STATE.delay_ms > 0:
            time.sleep(STATE.delay_ms / 1000.0)

        if STATE.fail_mode == "always":
            return send_json(start_response, 503, {"allow": False, "error": "forced failure"})
        if STATE.fail_mode == "rate":
            if random.random() < max(0.0, min(1.0, STATE.fail_rate)):
                return send_json(start_response, 503, {"allow": False, "error": "random failure"})

        try:
            try:
                length = int(environ.get('CONTENT_LENGTH', 0))
            except (ValueError, TypeError):
                length = 0
            body = environ['wsgi.input'].read(length) if length > 0 else b"{}"
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

        # Logging logic preserved
        if os.environ.get("AUTHZ_LOG", "0") == "1":
             logger.info(f"POST {path} topic={topic} allowed={allowed}")

        return send_json(start_response, 200, {"allow": allowed})

    return send_json(start_response, 404, {"error": "not found"})


def main() -> None:
    setup_logging(os.environ.get("AUTHZ_LOG_LEVEL", "INFO"))
    
    host = os.environ.get("AUTHZ_HOST", "0.0.0.0")
    port = int(os.environ.get("AUTHZ_PORT", "8081"))
    tls_enabled = os.environ.get("AUTHZ_TLS", "0") in {"1", "true", "TRUE"}
    tls_cert = os.environ.get("AUTHZ_TLS_CERT")
    tls_key = os.environ.get("AUTHZ_TLS_KEY")

    config = Config()
    config.bind = [f"{host}:{port}"]
    
    # Explicitly enable h2 (HTTP/2)
    config.alpn_protocols = ["h2"]

    if tls_enabled:
        if not tls_cert or not tls_key:
            raise SystemExit(
                "AUTHZ_TLS_CERT and AUTHZ_TLS_KEY must be set when AUTHZ_TLS=1"
            )
        config.certfile = tls_cert
        config.keyfile = tls_key
    else:
        # Important for benchmarks: This allows HTTP/2 over Cleartext (h2c)
        # Note: Browsers generally don't support h2c, but curl/nghttp2 do.
        pass

    # Hypercorn runs an asyncio loop to handle the network/H2 protocol frames,
    # but it offloads the 'application' (our WSGI function) to a worker thread
    # so that our logic can remain blocking without stalling the connection management.
    asyncio.run(serve(application, config))

if __name__ == "__main__":
    main()