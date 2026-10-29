"""
Authentication for Bayora Systems.
Callers present a server-signed bearer token (HMAC-SHA256). The role is read ONLY from the
verified token, never from a caller-supplied header. Fails closed.
A development-only header mode exists (BAYORA_DEV_HEADER_AUTH=1) and is OFF by default.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from enum import Enum

from .compat import HTTPException, RequestContext

TOKEN_TTL_SECONDS = int(os.environ.get("BAYORA_TOKEN_TTL_SECONDS", "3600"))


class Role(str, Enum):
    RED_TEAM = "RED_TEAM"
    BLUE_TEAM = "BLUE_TEAM"
    EVALUATOR = "EVALUATOR"


@dataclass(frozen=True)
class ActorIdentity:
    actor: str
    role: Role
    jti: str = ""
    exp: int = 0


def _deny(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": "AUTHENTICATION_FAILED", "code": code, "message": message})


def _secret() -> bytes:
    secret = os.environ.get("BAYORA_AUTH_SECRET", "")
    if not secret or secret.startswith("PLACEHOLDER"):
        raise _deny(503, "AUTH_NOT_CONFIGURED", "BAYORA_AUTH_SECRET is not configured (fail-closed).")
    return secret.encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(actor: str, role: Role, ttl: int = TOKEN_TTL_SECONDS) -> str:
    payload = _b64(json.dumps({"a": actor, "r": role.value, "j": os.urandom(8).hex(), "exp": int(time.time()) + ttl}).encode())
    sig = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify_token(token: str) -> ActorIdentity:
    try:
        payload, sig = token.split(".", 1)
    except ValueError:
        raise _deny(401, "AUTH_MALFORMED_TOKEN", "Malformed token.")
    expected = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise _deny(401, "AUTH_BAD_SIGNATURE", "Invalid token signature.")
    try:
        data = json.loads(_unb64(payload))
        role = Role(data["r"])
        actor = str(data["a"])[:80]
        exp = int(data["exp"])
    except Exception:
        raise _deny(401, "AUTH_MALFORMED_TOKEN", "Malformed token payload.")
    if exp < time.time():
        raise _deny(401, "AUTH_TOKEN_EXPIRED", "Token expired.")
    return ActorIdentity(actor=actor, role=role, jti=str(data.get("j", "")), exp=exp)


def credential_for_role(role: Role) -> str:
    env = {Role.RED_TEAM: "BAYORA_RED_WORKER_TOKEN", Role.BLUE_TEAM: "BAYORA_BLUE_WORKER_TOKEN",
           Role.EVALUATOR: "BAYORA_EVALUATOR_TOKEN"}[role]
    return os.environ.get(env, "")


_FAILS: dict = {}
MAX_FAILS, LOCK_SECONDS = 5, 60


def login(role_name: str, credential: str, actor: str) -> str:
    """Exchange a per-role credential (from env) for a signed bearer token."""
    try:
        role = Role((role_name or "").strip().upper())
    except ValueError:
        raise _deny(403, "AUTH_UNKNOWN_ROLE", "Unknown role.")
    now = time.time()
    fails = [t for t in _FAILS.get(role, []) if now - t < LOCK_SECONDS]
    expected = credential_for_role(role)
    if not expected or expected.startswith("PLACEHOLDER"):
        raise _deny(503, "AUTH_NOT_CONFIGURED", "Role credential not configured.")
    if len(expected) < 16 and os.environ.get("BAYORA_DEV_HEADER_AUTH") != "1":
        raise _deny(503, "AUTH_WEAK_CREDENTIAL", "Role credential must be >= 16 characters (fail-closed).")
    correct = hmac.compare_digest(credential or "", expected)
    # Guess throttling only: a CORRECT credential is never locked out, so attackers cannot lock real users out.
    if not correct and len(fails) >= MAX_FAILS:
        raise _deny(429, "AUTH_LOCKED_OUT", "Too many failed logins. Try again in a minute.")
    if not correct:
        fails.append(now)
        _FAILS[role] = fails
        raise _deny(401, "AUTH_BAD_CREDENTIAL", "Invalid credential.")
    _FAILS.pop(role, None)
    # Actor identity is assigned by the SERVER (env/role), never taken from the caller, so audit names can't be chosen.
    server_actor = os.environ.get(f"BAYORA_{role.value}_ACTOR", f"{role.value.lower()}-operator")
    return issue_token(server_actor, role)


def authenticate_request(request: RequestContext) -> ActorIdentity:
    auth = (request.header("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return verify_token(auth[7:].strip())
    if os.environ.get("BAYORA_DEV_HEADER_AUTH") == "1":  # development only, off by default
        raw_role = (request.header("x-bayora-role") or "").strip().upper()
        if raw_role:
            try:
                role = Role(raw_role)
            except ValueError:
                raise _deny(403, "AUTH_UNKNOWN_ROLE", "Unknown role.")
            return ActorIdentity(actor=(request.header("x-bayora-actor") or f"{role.value.lower()}-operator").strip(), role=role)
    raise _deny(401, "AUTH_MISSING_CREDENTIAL", "Missing bearer token (fail-closed).")
