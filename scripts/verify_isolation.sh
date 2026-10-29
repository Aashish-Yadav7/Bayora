#!/usr/bin/env bash
# REAL runtime isolation check: opens actual TCP/HTTP connections from inside running containers.
# Usage: cp .env.example .env (fill secrets) && docker compose up -d --build && ./scripts/verify_isolation.sh
set -u
fail=0
probe() { # <from-service> <host> <port> <expect: ok|blocked>
  if docker compose exec -T "$1" python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(3)
try: s.connect(('$2',$3)); sys.exit(0)
except Exception: sys.exit(1)" >/dev/null 2>&1; then got=ok; else got=blocked; fi
  if [ "$got" = "$4" ]; then echo "PASS  $1 -> $2:$3 ($got)"; else echo "FAIL  $1 -> $2:$3 expected $4, got $got"; fail=1; fi
}
probe red-worker  control-plane   8000 ok
probe blue-worker control-plane   8000 ok
probe red-worker  red-worker        8000 ok        # positive control: listener works
probe blue-worker blue-worker       8000 ok
probe red-worker  blue-worker     8000 blocked
probe blue-worker red-worker      8000 blocked
probe red-worker  target-adapter  8100 blocked
probe blue-worker target-adapter  8100 blocked
probe control-plane target-adapter 8100 ok
probe red-worker  1.1.1.1          443 blocked   # red-net is internal: no internet egress
probe blue-worker 1.1.1.1          443 blocked
[ $fail -eq 0 ] && echo "ISOLATION VERIFIED" || { echo "ISOLATION CHECK FAILED"; exit 1; }
