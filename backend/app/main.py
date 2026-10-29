"""
Entrypoint for the Bayora control plane (standard library HTTP server): `python3 -m backend.app.main`.
Demo data is OPT-IN (BAYORA_SEED_DEMO=1) so a real deployment never starts with fake tests/secrets.
"""
from __future__ import annotations

import os
import signal
import sys

from .api import create_bayora_app
from .compat import run_http_server

app = create_bayora_app(
    db_path=os.environ.get("BAYORA_DB_PATH", "bayora.db"),
    seed_demo_data=os.environ.get("BAYORA_SEED_DEMO", "0") == "1",
)


def _shutdown(*_: object) -> None:
    app.db.close()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    port = int(os.environ.get("BAYORA_BACKEND_PORT", "8000"))
    host = os.environ.get("BAYORA_BACKEND_HOST", "127.0.0.1")
    print(f"[Bayora Control Plane] Starting on http://{host}:{port} ...", flush=True)
    run_http_server(app, host=host, port=port)
