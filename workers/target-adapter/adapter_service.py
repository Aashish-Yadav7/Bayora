"""
Bayora Systems - Target adapter service (control-net only).
HTTP contract:
  GET  /health                      -> 200 {"status": "ok", "adapter_type": ..., "is_mock": ...}
  POST /evaluate (Bearer token)     -> 200 evaluation output | 400 bad input | 401 bad token | 413 too large
Requests need `Authorization: Bearer $BAYORA_ADAPTER_TOKEN` (shared only with the control plane).
Evaluation runs under a hard timeout (BAYORA_EXECUTION_TIMEOUT_MS) and errors never leak internals.
"""
from __future__ import annotations

import dataclasses
import hmac
import json
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from backend.app.adapters import DeterministicMockLLMAdapter, GeminiAdapter

MAX_BODY = 256 * 1024
TIMEOUT_S = int(os.environ.get("BAYORA_EXECUTION_TIMEOUT_MS", "5000")) / 1000
TOKEN = os.environ.get("BAYORA_ADAPTER_TOKEN", "")
_pool = ThreadPoolExecutor(max_workers=4)


def get_adapter():
    if os.environ.get("BAYORA_TARGET_ADAPTER_MODE") == "GEMINI_LIVE_V1":
        return GeminiAdapter()
    return DeterministicMockLLMAdapter()


class Handler(BaseHTTPRequestHandler):
    timeout = 15  # drop stalled clients

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/health":
            a = get_adapter()
            return self._send(200, {"status": "ok", "adapter_type": a.ADAPTER_TYPE, "is_mock": a.ADAPTER_TYPE.startswith("MOCK")})
        self._send(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:
        if self.path != "/evaluate":
            return self._send(404, {"error": "NOT_FOUND"})
        auth = self.headers.get("Authorization", "")
        if not TOKEN or not auth.startswith("Bearer ") or not hmac.compare_digest(auth[7:], TOKEN):
            return self._send(401, {"error": "UNAUTHORIZED"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "BAD_REQUEST"})
        if length <= 0 or length > MAX_BODY:
            return self._send(413 if length > MAX_BODY else 400, {"error": "BAD_BODY_SIZE"})
        try:
            body = json.loads(self.rfile.read(length))
            kwargs = {
                "test_id": str(body["test_id"]), "run_id": str(body["run_id"]),
                "target_model": str(body["target_model"]),
                "red_payloads": list(body["red_payloads"]), "blue_defenses": list(body["blue_defenses"]),
            }
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"error": "INVALID_REQUEST"})
        future = _pool.submit(get_adapter().evaluate_isolated_run, **kwargs)
        try:
            out = future.result(timeout=TIMEOUT_S)
        except FuturesTimeout:
            return self._send(504, {"error": "TARGET_TIMEOUT"})
        except Exception:
            return self._send(502, {"error": "TARGET_FAILURE"})
        self._send(200, dataclasses.asdict(out))


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("PLACEHOLDER"):
        raise SystemExit("BAYORA_ADAPTER_TOKEN must be set")
    port = int(os.environ.get("BAYORA_ADAPTER_PORT", "8100"))
    print(f"[target-adapter] listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
