"""
SQLite storage layer for Bayora Systems.
Enforces strict table separation for:
1. tests (test lifecycle & non-sensitive metadata)
2. red_payloads (isolated Red Team attack artifacts)
3. blue_defenses (isolated Blue Team defense configurations)
4. evaluation_results (isolated target evaluation runs)
5. audit_events (tamper-evident (hash-chained) security audit trail with zero secret/payload copying)
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional


DEFAULT_DB_PATH = os.environ.get("BAYORA_DB_PATH", "bayora.db")


class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("BAYORA_DB_PATH", DEFAULT_DB_PATH)
        self._persistent_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._persistent_conn.row_factory = sqlite3.Row
        self.init_db()

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        if self._persistent_conn is not None:
            try:
                yield self._persistent_conn
                self._persistent_conn.commit()
            except Exception:
                self._persistent_conn.rollback()
                raise
        else:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def close(self) -> None:
        if self._persistent_conn is not None:
            self._persistent_conn.close()
            self._persistent_conn = None

    def _harden_file(self) -> None:
        if self.db_path != ":memory:" and os.path.exists(self.db_path):
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def init_db(self) -> None:
        self._init_schema()
        with self.connection() as conn:  # migrate DBs created before the hash chain existed
            cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
            for col in ("prev_hash", "event_hash"):
                if col not in cols:
                    conn.execute(f"ALTER TABLE audit_events ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
        self._harden_file()

    def _init_schema(self) -> None:
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS tests (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    target_model TEXT NOT NULL,
                    adapter_mode TEXT NOT NULL,
                    state TEXT NOT NULL,
                    current_run_id TEXT,
                    created_by_role TEXT NOT NULL,
                    created_by_actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS red_payloads (
                    id TEXT PRIMARY KEY,
                    test_id TEXT NOT NULL,
                    author_actor TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity_tier TEXT NOT NULL,
                    payload_text TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(test_id) REFERENCES tests(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS blue_defenses (
                    id TEXT PRIMARY KEY,
                    test_id TEXT NOT NULL,
                    author_actor TEXT NOT NULL,
                    defense_name TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    defense_config_secret TEXT NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(test_id) REFERENCES tests(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_results (
                    id TEXT PRIMARY KEY,
                    test_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    adapter_type TEXT NOT NULL,
                    is_mock INTEGER NOT NULL,
                    target_config_json TEXT NOT NULL,
                    total_probes INTEGER NOT NULL,
                    blocked_count INTEGER NOT NULL,
                    bypassed_count INTEGER NOT NULL,
                    resilience_score REAL NOT NULL,
                    summary_notes TEXT NOT NULL,
                    probe_outcomes_json TEXT NOT NULL,
                    execution_ms INTEGER NOT NULL,
                    run_status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(test_id) REFERENCES tests(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    run_id TEXT,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    state_transition TEXT,
                    reason_code TEXT NOT NULL,
                    prev_hash TEXT NOT NULL DEFAULT '',
                    event_hash TEXT NOT NULL DEFAULT ''
                )
                """
            )
