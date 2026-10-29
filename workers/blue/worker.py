"""
Bayora Systems - Blue Team worker. Attached ONLY to blue-net (internal); reaches the control plane,
which is the sole mediator. Authenticates with a bearer token obtained via /api/auth/login.
"""
from __future__ import annotations

import json, os, time, urllib.request

CONTROL_PLANE_URL = os.environ.get("BAYORA_CONTROL_PLANE_URL", "http://control-plane:8000")
ACTOR_ID = os.environ.get("BAYORA_BLUE_ACTOR", "blue-worker-node@blue.bayora")
CREDENTIAL = os.environ.get("BAYORA_BLUE_WORKER_TOKEN", "")
_token = {"value": None, "exp": 0.0}


def _call(path, body):
    req = urllib.request.Request(CONTROL_PLANE_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **_auth()}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def _auth():
    if time.time() > _token["exp"]:
        req = urllib.request.Request(CONTROL_PLANE_URL + "/api/auth/login", method="POST",
                                     data=json.dumps({"role": "BLUE_TEAM", "credential": CREDENTIAL, "actor": ACTOR_ID}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            _token["value"] = json.loads(resp.read().decode())["token"]
        _token["exp"] = time.time() + 3000  # tokens live 3600s by default
    return {"Authorization": "Bearer " + _token["value"]}


def submit_defense_via_control_plane(test_id: str, defense_name: str, rule_type: str, secret_rule: str) -> dict:
    return _call(f"/api/tests/{test_id}/defenses",
                 {"defense_name": defense_name, "rule_type": rule_type, "defense_config_secret": secret_rule})



import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _serve():
    HTTPServer(("0.0.0.0", 8000), _Health).serve_forever()  # probe target for scripts/verify_isolation.sh


if __name__ == "__main__":
    threading.Thread(target=_serve, daemon=True).start()
    print("[blue-worker] ready; authenticating to control plane", flush=True)
    _auth()
    while True:
        time.sleep(30)
