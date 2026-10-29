"""
Audit Evidence Logger (tamper-EVIDENT hash chain; not tamper-proof against a DB admin who rewrites the whole chain) for Bayora Systems.
Every allowed and denied request records a tamper-evident (hash-chained) audit event with:
- timestamp (ISO-8601 UTC)
- test_id
- run_id
- actor / role
- action
- resource
- allow/deny decision (ALLOW | DENY)
- state_transition (e.g., Draft->Ready, Ready->Running, or attempted invalid transition)

NON-NEGOTIABLE: Never copy raw payloads, defense configs, or secrets into audit logs.
Audit events reference artifacts by ID and SHA-256 hash metadata only.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .database import DatabaseManager


SECRET_REDACTION_PATTERNS = [
    re.compile(r"(api[_-]?key|secret|token|password|payload_text|defense_config_secret)\s*[:=]\s*\S+", re.IGNORECASE),
]


def sanitize_resource_ref(resource: str) -> str:
    """Ensures resource references only contain safe identifiers/paths and never raw secrets."""
    cleaned = resource.strip()
    for pattern in SECRET_REDACTION_PATTERNS:
        cleaned = pattern.sub("[REDACTED_METADATA_ONLY]", cleaned)
    if len(cleaned) > 180:
        cleaned = cleaned[:180] + "...[TRUNCATED_REF]"
    return cleaned


_FIELDS = ("id", "timestamp", "test_id", "run_id", "actor", "role", "action", "resource",
           "decision", "state_transition", "reason_code")


def _hash_event(prev_hash: str, values: tuple) -> str:
    material = prev_hash + "|" + "|".join("" if v is None else str(v) for v in values)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def record(
        self,
        *,
        test_id: str,
        actor: str,
        role: str,
        action: str,
        resource: str,
        decision: str,
        run_id: Optional[str] = None,
        state_transition: Optional[str] = None,
        reason_code: str = "OK",
    ) -> Dict[str, Any]:
        if decision not in ("ALLOW", "DENY"):
            raise ValueError("Audit decision must be ALLOW or DENY")

        event_id = f"aud-{uuid.uuid4().hex}"
        timestamp = datetime.now(timezone.utc).isoformat()
        safe_resource = sanitize_resource_ref(resource)

        values = (event_id, timestamp, test_id, run_id, actor, role, action, safe_resource,
                  decision, state_transition, reason_code)
        with self.db.connection() as conn:
            conn.execute("BEGIN IMMEDIATE") if conn.in_transaction is False else None
            last = conn.execute("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1").fetchone()
            prev_hash = last["event_hash"] if last else ""
            conn.execute(
                """
                INSERT INTO audit_events (
                    id, timestamp, test_id, run_id, actor, role,
                    action, resource, decision, state_transition, reason_code, prev_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values + (prev_hash, _hash_event(prev_hash, values)),
            )

        return {
            "id": event_id,
            "timestamp": timestamp,
            "test_id": test_id,
            "run_id": run_id,
            "actor": actor,
            "role": role,
            "action": action,
            "resource": safe_resource,
            "decision": decision,
            "state_transition": state_transition,
            "reason_code": reason_code,
        }

    def list_events(self, test_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            cursor = conn.cursor()
            if test_id:
                cursor.execute(
                    """
                    SELECT id, timestamp, test_id, run_id, actor, role,
                           action, resource, decision, state_transition, reason_code
                    FROM audit_events
                    WHERE test_id = ?
                    ORDER BY timestamp DESC, rowid DESC
                    LIMIT ?
                    """,
                    (test_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, timestamp, test_id, run_id, actor, role,
                           action, resource, decision, state_transition, reason_code
                    FROM audit_events
                    ORDER BY timestamp DESC, rowid DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def verify_chain(self) -> Dict[str, Any]:
        """Recompute the whole hash chain; report the first broken record (edit, delete or reorder)."""
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(_FIELDS)}, prev_hash, event_hash FROM audit_events ORDER BY rowid ASC"
            ).fetchall()
        prev = ""
        for i, r in enumerate(rows):
            values = tuple(r[f] for f in _FIELDS)
            if r["prev_hash"] != prev or r["event_hash"] != _hash_event(prev, values):
                return {"valid": False, "checked": i + 1, "first_broken_event_id": r["id"]}
            prev = r["event_hash"]
        return {"valid": True, "checked": len(rows), "first_broken_event_id": None}

    # ---- signed checkpoints: defeat a full-chain rewrite by anchoring head+count outside the database ----
    @staticmethod
    def _cp_key() -> bytes:
        key = os.environ.get("BAYORA_AUDIT_KEY") or os.environ.get("BAYORA_AUTH_SECRET", "")
        if not key or key.startswith("PLACEHOLDER"):
            raise ValueError("BAYORA_AUDIT_KEY (or BAYORA_AUTH_SECRET) is not configured")
        return ("audit-checkpoint:" + key).encode()

    def create_checkpoint(self) -> Dict[str, Any]:
        """Return a signed {count, head_hash, timestamp}. Store it OFF the database (file share, email, git)."""
        chain = self.verify_chain()
        if not chain["valid"]:
            raise ValueError("Refusing to checkpoint a broken chain")
        with self.db.connection() as conn:
            row = conn.execute("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1").fetchone()
        head = row["event_hash"] if row else ""
        ts = datetime.now(timezone.utc).isoformat()
        msg = f"{chain['checked']}|{head}|{ts}".encode()
        return {"count": chain["checked"], "head_hash": head, "timestamp": ts,
                "signature": hmac.new(self._cp_key(), msg, hashlib.sha256).hexdigest()}

    def verify_checkpoint(self, cp: Dict[str, Any]) -> Dict[str, Any]:
        """Check a saved checkpoint against the live DB: detects edits, deletions AND full-chain rewrites."""
        try:
            count, head, ts, sig = int(cp["count"]), str(cp["head_hash"]), str(cp["timestamp"]), str(cp["signature"])
        except (KeyError, TypeError, ValueError):
            return {"valid": False, "reason": "MALFORMED_CHECKPOINT"}
        expected = hmac.new(self._cp_key(), f"{count}|{head}|{ts}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return {"valid": False, "reason": "BAD_CHECKPOINT_SIGNATURE"}
        chain = self.verify_chain()
        if not chain["valid"]:
            return {"valid": False, "reason": "CHAIN_BROKEN", "first_broken_event_id": chain["first_broken_event_id"]}
        with self.db.connection() as conn:
            row = conn.execute("SELECT event_hash FROM audit_events ORDER BY rowid ASC LIMIT 1 OFFSET ?",
                               (max(count - 1, 0),)).fetchone()
        if count == 0:
            return {"valid": True, "reason": "EMPTY_CHECKPOINT"}
        if chain["checked"] < count or not row or row["event_hash"] != head:
            return {"valid": False, "reason": "HISTORY_REWRITTEN_OR_TRUNCATED"}
        return {"valid": True, "reason": "OK", "events_since_checkpoint": chain["checked"] - count}
