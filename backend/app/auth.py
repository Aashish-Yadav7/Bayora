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
import re
import struct
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
    iat: int = 0


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
    payload = _b64(json.dumps({"a": actor, "r": role.value, "j": os.urandom(8).hex(), "i": int(time.time() * 1000), "exp": int(time.time()) + ttl}).encode())
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
    return ActorIdentity(actor=actor, role=role, jti=str(data.get("j", "")), exp=exp, iat=int(data.get("i", 0)))


def credential_for_role(role: Role) -> str:
    env = {Role.RED_TEAM: "BAYORA_RED_WORKER_TOKEN", Role.BLUE_TEAM: "BAYORA_BLUE_WORKER_TOKEN",
           Role.EVALUATOR: "BAYORA_EVALUATOR_TOKEN"}[role]
    return os.environ.get(env, "")


MAX_FAILS, LOCK_SECONDS = 5, 60
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
_DUMMY_HASH: list = []


def ensure_tables(db) -> None:
    with db.connection() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, role TEXT NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS login_failures (key TEXT NOT NULL, ts REAL NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS test_participants (test_id TEXT NOT NULL, role TEXT NOT NULL, actor TEXT NOT NULL, PRIMARY KEY (test_id, role, actor))")
        c.execute("CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL)")
        cols = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
        for col, ddl in (("disabled", "INTEGER NOT NULL DEFAULT 0"), ("totp_secret", "TEXT"), ("totp_pending", "TEXT"),
                         ("totp_last", "INTEGER NOT NULL DEFAULT 0"), ("valid_after", "INTEGER NOT NULL DEFAULT 0")):
            if col not in cols:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")


# ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


def totp_at(secret: str, t: float = None) -> str:
    return _totp(secret, int((time.time() if t is None else t) // 30))


def verify_totp(secret: str, code: str, last_used: int = 0, t: float = None):
    """Return the accepted counter, or None. Accepts +-1 step of clock drift; a counter can be used only once."""
    now = int((time.time() if t is None else t) // 30)
    for off in (-1, 0, 1):
        counter = now + off
        if counter > last_used and hmac.compare_digest(_totp(secret, counter), code or ""):
            return counter
    return None


_RESERVED = re.compile(r"^(red_team|blue_team|evaluator)-operator$", re.I)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


def create_user(db, username: str, role: Role, password: str) -> None:
    if not _USERNAME_RE.match(username or ""):
        raise ValueError("Username must be 3-40 characters: letters, digits, _ . -")
    if _RESERVED.match(username):
        raise ValueError("That username is reserved")
    if len(password or "") < 12:
        raise ValueError("Password must be at least 12 characters")
    from datetime import datetime, timezone
    with db.connection() as c:
        if c.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise ValueError("User already exists")
        c.execute("INSERT INTO users (username, role, pw_hash, created_at) VALUES (?, ?, ?, ?)",
                  (username, role.value, hash_password(password), datetime.now(timezone.utc).isoformat()))


def _fail_count(db, key: str) -> int:
    with db.connection() as c:
        c.execute("DELETE FROM login_failures WHERE ts < ?", (time.time() - LOCK_SECONDS,))
        return c.execute("SELECT COUNT(*) FROM login_failures WHERE key = ?", (key,)).fetchone()[0]


def _throttle_or_fail(db, key: str, correct: bool) -> None:
    """Persistent (DB) guess throttling. A CORRECT credential is never locked out, so attackers cannot lock users out."""
    if correct:
        with db.connection() as c:
            c.execute("DELETE FROM login_failures WHERE key = ?", (key,))
        return
    if _fail_count(db, key) >= MAX_FAILS:
        raise _deny(429, "AUTH_LOCKED_OUT", "Too many failed logins. Try again in a minute.")
    with db.connection() as c:
        c.execute("INSERT INTO login_failures (key, ts) VALUES (?, ?)", (key, time.time()))
    raise _deny(401, "AUTH_BAD_CREDENTIAL", "Invalid credentials.")


def login_user(db, username: str, password: str, otp: str = ""):
    """Per-person login (+ optional TOTP). Role and actor come from the users table, never from the caller."""
    with db.connection() as c:
        row = c.execute("SELECT username, role, pw_hash, disabled, totp_secret, totp_last FROM users WHERE username = ?",
                        (username or "",)).fetchone()
    if not _DUMMY_HASH:
        _DUMMY_HASH.append(hash_password(os.urandom(8).hex()))
    pw_ok = verify_password(password or "", row["pw_hash"] if row else _DUMMY_HASH[0]) and row is not None and not row["disabled"]
    key = f"user:{(username or '').lower()}"
    if not pw_ok:
        _throttle_or_fail(db, key, False)  # raises
    if row["totp_secret"]:
        if not (otp or "").strip():
            raise _deny(401, "AUTH_OTP_REQUIRED", "One-time code required.")  # not counted: password was right
        counter = verify_totp(row["totp_secret"], otp.strip(), row["totp_last"] or 0)
        if counter is None:
            _throttle_or_fail(db, key, False)  # wrong OTP counts toward the lockout; never cleared by a correct password
        with db.connection() as c:
            c.execute("UPDATE users SET totp_last = ? WHERE username = ?", (counter, row["username"]))
    _throttle_or_fail(db, key, True)
    role = Role(row["role"])
    return issue_token(row["username"], role), role.value


def set_password(db, username: str, new_password: str) -> None:
    if len(new_password or "") < 12:
        raise ValueError("Password must be at least 12 characters")
    with db.connection() as c:
        c.execute("UPDATE users SET pw_hash = ?, valid_after = ? WHERE username = ?",
                  (hash_password(new_password), int(time.time() * 1000), username))


def login(role_name: str, credential: str, actor: str, db):
    """Shared per-role credential login (workers/demo). Actor is server-assigned."""
    try:
        role = Role((role_name or "").strip().upper())
    except ValueError:
        raise _deny(403, "AUTH_UNKNOWN_ROLE", "Unknown role.")
    expected = credential_for_role(role)
    if not expected or expected.startswith("PLACEHOLDER"):
        raise _deny(503, "AUTH_NOT_CONFIGURED", "Role credential not configured.")
    if len(expected) < 16 and os.environ.get("BAYORA_DEV_HEADER_AUTH") != "1":
        raise _deny(503, "AUTH_WEAK_CREDENTIAL", "Role credential must be >= 16 characters (fail-closed).")
    _throttle_or_fail(db, f"role:{role.value}", hmac.compare_digest(credential or "", expected))
    server_actor = os.environ.get(f"BAYORA_{role.value}_ACTOR", f"{role.value.lower()}-operator")
    return issue_token(server_actor, role), role.value


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
