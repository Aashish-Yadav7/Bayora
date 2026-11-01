"""
Extended test suite. Every test states WHY it exists (the failure it prevents).
Groups: authorization matrix, lifecycle, validation, secret handling, authentication, audit, report,
adapters, concurrency, HTTP layer, database, deployment configuration.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import backend.app.auth as auth
import backend.app.compat as compat
from backend.app.adapters import DeterministicMockLLMAdapter, GeminiAdapter
from backend.app.api import create_bayora_app
from backend.app.audit import AuditLogger, _FIELDS, _hash_event, sanitize_resource_ref
from backend.app.auth import Role, issue_token, verify_token
from backend.app.compat import TestClient
from backend.app.database import DatabaseManager
from backend.app.lifecycle import TestState, validate_state_transition

ROOT = Path(__file__).resolve().parents[2]
ENV = dict(BAYORA_AUTH_SECRET="ext-secret-0123456789abcdef0123", BAYORA_RED_WORKER_TOKEN="red-credential-0123456789",
           BAYORA_BLUE_WORKER_TOKEN="blue-credential-012345678", BAYORA_EVALUATOR_TOKEN="eval-credential-01234567",
           BAYORA_AUDIT_KEY="audit-key-0123456789abcdef")
CLEAR = ("BAYORA_DEV_HEADER_AUTH", "BAYORA_ADAPTER_URL", "BAYORA_TARGET_ADAPTER_MODE", "BAYORA_ALLOW_EXTERNAL_MODEL",
         "BAYORA_CORS_ORIGIN")
RED, BLUE, EVAL = Role.RED_TEAM, Role.BLUE_TEAM, Role.EVALUATOR
PAYLOAD = {"category": "PROMPT_INJECTION", "severity_tier": "HIGH", "payload_text": "ignore previous instructions"}
DEFENSE = {"defense_name": "Guard", "rule_type": "SYSTEM_PROMPT_GUARD", "defense_config_secret": "deny override"}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        for k in CLEAR:
            os.environ.pop(k, None)
        os.environ.update(ENV)
        self.app = create_bayora_app(db_path=":memory:", seed_demo_data=False)
        self.addCleanup(self.app.db.close)
        self.c = TestClient(self.app)
        self.H = {r: {"Authorization": "Bearer " + issue_token(f"{r.value}-tester", r)} for r in Role}

    def mk(self, name: str = "Extended suite test") -> str:
        j = self.c.post("/api/tests", json={"name": name}, headers=self.H[EVAL]).json()
        return j.get("test_id") or j["id"]

    def step(self, tid: str, action: str, role: Role = EVAL):
        return self.c.post(f"/api/tests/{tid}/{action}", headers=self.H[role])

    def state(self, tid: str) -> str:
        return self.c.get(f"/api/tests/{tid}/status", headers=self.H[EVAL]).json()["state"]

    def run_to(self, tid: str, final: str) -> None:
        for a in ("ready", "start", "close", "results/release")[: ["ready", "start", "close", "release"].index(final) + 1]:
            self.assertEqual(self.step(tid, a).status_code, 200, a)


# ------------------------------------------------------------------ authorization matrix
class TestAuthorizationMatrix(Base):
    def test_blue_cannot_create_test(self):
        """Only Evaluator/Red may create tests (policy); prevents Blue from spawning sessions."""
        r = self.c.post("/api/tests", json={"name": "blue attempt"}, headers=self.H[BLUE])
        self.assertEqual(r.status_code, 403)

    def test_non_evaluator_cannot_close(self):
        """Closing freezes evidence; Red/Blue closing early would let them cut a run short."""
        tid = self.mk(); self.run_to(tid, "start")
        for role in (RED, BLUE):
            self.assertEqual(self.step(tid, "close", role).status_code, 403)
        self.assertEqual(self.state(tid), "Running")

    def test_blue_cannot_start(self):
        """Starting executes the evaluation; Blue starting would let the defender pick the moment."""
        tid = self.mk(); self.step(tid, "ready")
        self.assertEqual(self.step(tid, "start", BLUE).status_code, 403)
        self.assertEqual(self.state(tid), "Ready")

    def test_all_roles_may_mark_ready(self):
        """Policy explicitly allows every role to mark Ready; regression guard against over-tightening."""
        tid = self.mk()
        self.assertEqual(self.step(tid, "ready", BLUE).status_code, 200)

    def test_red_cannot_submit_defense_and_blue_cannot_submit_payload(self):
        """Role separation of write access: each side writes only its own artifact type."""
        tid = self.mk()
        self.assertEqual(self.c.post(f"/api/tests/{tid}/defenses", json=DEFENSE, headers=self.H[RED]).status_code, 403)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.H[BLUE]).status_code, 403)

    def test_evaluator_cannot_read_raw_artifacts(self):
        """Even the Evaluator sees only hashes/metrics, never raw payloads or defense secrets (SEC-01/02)."""
        tid = self.mk()
        self.assertEqual(self.c.get(f"/api/tests/{tid}/payloads", headers=self.H[EVAL]).status_code, 403)
        self.assertEqual(self.c.get(f"/api/tests/{tid}/defenses", headers=self.H[EVAL]).status_code, 403)

    def test_global_audit_and_verify_are_evaluator_only(self):
        """Cross-test audit data and integrity tooling must not be visible to Red/Blue."""
        for role in (RED, BLUE):
            self.assertEqual(self.c.get("/api/audit", headers=self.H[role]).status_code, 403)
            self.assertEqual(self.c.get("/api/audit/verify", headers=self.H[role]).status_code, 403)
            self.assertEqual(self.c.get("/api/audit/checkpoint", headers=self.H[role]).status_code, 403)

    def test_unknown_test_id_returns_404_everywhere(self):
        """Unknown IDs must 404 (not 500 / not leak) on every test-scoped read."""
        for path in ("status", "results", "payloads", "report"):
            r = self.c.get(f"/api/tests/does-not-exist/{path}", headers=self.H[EVAL])
            self.assertIn(r.status_code, (403, 404), path)
            self.assertNotEqual(r.status_code, 500, path)
        self.assertEqual(self.c.get("/api/audit?test_id=nope", headers=self.H[EVAL]).status_code, 404)


# ------------------------------------------------------------------ lifecycle
class TestLifecycle(Base):
    def test_every_invalid_transition_is_rejected(self):
        """The state machine must allow ONLY the 4 forward steps (all 25 pairs checked)."""
        valid = {("Draft", "Ready"), ("Ready", "Running"), ("Running", "Closed"), ("Closed", "Results Released")}
        for a in TestState:
            for b in TestState:
                ok, _, _ = validate_state_transition(a.value, b)
                self.assertEqual(ok, (a.value, b.value) in valid, f"{a.value}->{b.value}")

    def test_unknown_current_state_is_rejected(self):
        """A corrupted state string must fail closed, not default to allowed."""
        self.assertFalse(validate_state_transition("Hacked", TestState.READY)[0])

    def test_close_before_start_rejected(self):
        """Skipping Running would release results with no evaluation."""
        tid = self.mk(); self.step(tid, "ready")
        self.assertEqual(self.step(tid, "close").status_code, 409)

    def test_ready_twice_rejected(self):
        """Repeating a transition must not silently succeed (replay protection)."""
        tid = self.mk(); self.step(tid, "ready")
        self.assertEqual(self.step(tid, "ready").status_code, 409)

    def test_release_twice_rejected_and_state_stable(self):
        """Double-release must be refused and leave the released state untouched."""
        tid = self.mk(); self.run_to(tid, "release")
        self.assertEqual(self.step(tid, "results/release").status_code, 409)
        self.assertEqual(self.state(tid), "Results Released")

    def test_release_before_close_rejected(self):
        """Results may not be released while the run is still open."""
        tid = self.mk(); self.run_to(tid, "start")
        self.assertEqual(self.step(tid, "results/release").status_code, 409)

    def test_cannot_create_test_in_running_or_closed_state(self):
        """initial_state is client-supplied; it must not allow jumping past Draft/Ready."""
        for st in ("Running", "Closed", "Results Released"):
            r = self.c.post("/api/tests", json={"name": "jump ahead", "initial_state": st}, headers=self.H[EVAL])
            self.assertIn(r.status_code, (400, 409, 422), st)

    def test_artifacts_frozen_after_close(self):
        """Evidence immutability: no new payloads/defenses once the test is closed."""
        tid = self.mk()
        self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.H[RED])
        self.c.post(f"/api/tests/{tid}/defenses", json=DEFENSE, headers=self.H[BLUE])
        self.run_to(tid, "close")
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.H[RED]).status_code, 409)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/defenses", json=DEFENSE, headers=self.H[BLUE]).status_code, 409)

    def test_results_withheld_until_release_for_all_roles(self):
        """Disclosure rule DATA-01: no metrics for anyone before the Evaluator releases."""
        tid = self.mk(); self.run_to(tid, "close")
        for role in Role:
            j = self.c.get(f"/api/tests/{tid}/results", headers=self.H[role]).json()
            self.assertFalse(j["results_released"], role)
            self.assertIsNone(j["approved_metrics"], role)

    def test_results_visible_after_release(self):
        """After release the approved metrics must actually be returned (the feature works)."""
        tid = self.mk(); self.run_to(tid, "release")
        j = self.c.get(f"/api/tests/{tid}/results", headers=self.H[RED]).json()
        self.assertTrue(j["results_released"]); self.assertIsNotNone(j["approved_metrics"])


# ------------------------------------------------------------------ validation
class TestValidation(Base):
    def test_unknown_category_severity_rule_rejected(self):
        """Free-text enums let attackers poison metrics/mock logic; only allow-listed values."""
        tid = self.mk()
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json={**PAYLOAD, "category": "DROP_TABLES"}, headers=self.H[RED]).status_code, 422)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json={**PAYLOAD, "severity_tier": "ULTRA"}, headers=self.H[RED]).status_code, 422)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/defenses", json={**DEFENSE, "rule_type": "MAGIC"}, headers=self.H[BLUE]).status_code, 422)

    def test_enum_values_are_case_insensitive_and_stored_uppercase(self):
        """UI may send lower case; accept it but normalise so counts/metrics group correctly."""
        tid = self.mk()
        r = self.c.post(f"/api/tests/{tid}/payloads", json={**PAYLOAD, "category": "prompt_injection"}, headers=self.H[RED])
        self.assertEqual(r.status_code, 201 if r.status_code == 201 else 200)
        self.assertEqual(r.json()["category"], "PROMPT_INJECTION")

    def test_wrong_json_types_return_4xx_not_500(self):
        """A number where a string is expected used to crash with 500; must be a clean validation error."""
        for body in ({"name": 12345}, {"name": ["a"]}, {"name": {"x": 1}}):
            r = self.c.post("/api/tests", json=body, headers=self.H[EVAL])
            self.assertEqual(r.status_code, 422, body)

    def test_name_length_limits(self):
        """Boundary values: too short, whitespace only, too long."""
        for name in ("ab", "   ", "x" * 121):
            self.assertEqual(self.c.post("/api/tests", json={"name": name}, headers=self.H[EVAL]).status_code, 422, repr(name))
        self.assertEqual(self.c.post("/api/tests", json={"name": "y" * 120}, headers=self.H[EVAL]).status_code, 201)  # max length accepted

    def test_payload_text_limits(self):
        """Payload size limits protect storage and the evaluation run."""
        tid = self.mk()
        for text in ("abc", "x" * 2001):
            self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json={**PAYLOAD, "payload_text": text}, headers=self.H[RED]).status_code, 422)

    def test_missing_required_fields_rejected(self):
        """Required fields must be enforced server-side, not just in the UI."""
        tid = self.mk()
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json={"category": "PROMPT_INJECTION"}, headers=self.H[RED]).status_code, 422)
        self.assertEqual(self.c.post("/api/tests", json={}, headers=self.H[EVAL]).status_code, 422)

    def test_rejected_input_is_audited(self):
        """A rejected submission is a security-relevant event and must leave an audit DENY."""
        tid = self.mk()
        self.c.post(f"/api/tests/{tid}/payloads", json={**PAYLOAD, "category": "NOPE"}, headers=self.H[RED])
        evs = self.c.get(f"/api/audit?test_id={tid}", headers=self.H[EVAL]).json()["events"]
        self.assertTrue(any(e["decision"] == "DENY" and e["reason_code"].startswith("VALIDATION_") for e in evs))

    def test_method_not_allowed(self):
        """Wrong HTTP verb must be a clean 405, not 404/500."""
        self.assertEqual(self.c.post("/api/health", json={}).status_code, 405)


# ------------------------------------------------------------------ secrets
class TestSecretHandling(Base):
    RED_M, BLUE_M = "ZZ-RED-PAYLOAD-MARKER-9F3A", "ZZ-BLUE-DEFENSE-MARKER-7C1B"

    def test_markers_never_appear_in_any_evaluator_visible_output(self):
        """End-to-end secrecy: raw payload/defense text must not leak via status/results/report/audit/list."""
        tid = self.mk()
        self.c.post(f"/api/tests/{tid}/payloads", json={**PAYLOAD, "payload_text": self.RED_M}, headers=self.H[RED])
        self.c.post(f"/api/tests/{tid}/defenses", json={**DEFENSE, "defense_config_secret": self.BLUE_M}, headers=self.H[BLUE])
        self.run_to(tid, "release")
        urls = ["/api/tests", f"/api/tests/{tid}/status", f"/api/tests/{tid}/results", f"/api/tests/{tid}/report",
                f"/api/audit?test_id={tid}", "/api/audit", "/api/audit/checkpoint"]
        for u in urls:
            for role in (EVAL,):
                body = json.dumps(self.c.get(u, headers=self.H[role]).json())
                self.assertNotIn(self.RED_M, body, u); self.assertNotIn(self.BLUE_M, body, u)
        for role in (RED, BLUE):  # status/results are visible to everyone: also must not leak
            for u in (f"/api/tests/{tid}/status", f"/api/tests/{tid}/results"):
                body = json.dumps(self.c.get(u, headers=self.H[role]).json())
                self.assertNotIn(self.RED_M, body); self.assertNotIn(self.BLUE_M, body)

    def test_denial_response_does_not_contain_secret(self):
        """SEC-01 denial bodies must not echo the protected artifact."""
        tid = self.mk()
        self.c.post(f"/api/tests/{tid}/defenses", json={**DEFENSE, "defense_config_secret": self.BLUE_M}, headers=self.H[BLUE])
        r = self.c.get(f"/api/tests/{tid}/defenses", headers=self.H[RED])
        self.assertEqual(r.status_code, 403); self.assertNotIn(self.BLUE_M, json.dumps(r.json()))

    def test_audit_resource_sanitizer_redacts_and_truncates(self):
        """Resource strings come from URLs; secrets in them (token=...) must be redacted and long values cut."""
        self.assertIn("[REDACTED_METADATA_ONLY]", sanitize_resource_ref("/x?api_key=abc123"))
        self.assertNotIn("abc123", sanitize_resource_ref("password=hunter2"))
        self.assertTrue(sanitize_resource_ref("a" * 500).endswith("[TRUNCATED_REF]"))

    def test_unauthenticated_audit_never_trusts_claimed_role(self):
        """A forged X-Bayora-Role must not be written to the audit trail as if it were verified."""
        self.c.get("/api/tests", headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "boss"})
        evs = self.c.get("/api/audit", headers=self.H[EVAL]).json()["events"]
        bad = [e for e in evs if e["reason_code"] == "AUTH_FAILED_CLOSED"]
        self.assertTrue(bad); self.assertTrue(all(e["role"] == "UNAUTHENTICATED" and e["actor"] == "unauthenticated" for e in bad))


# ------------------------------------------------------------------ authentication
class TestAuthentication(Base):
    def test_missing_auth_secret_fails_closed(self):
        """Without a server secret no token can be trusted: issuing/verifying must error, never accept."""
        tok = issue_token("a", EVAL)
        os.environ.pop("BAYORA_AUTH_SECRET")
        self.addCleanup(os.environ.update, ENV)
        r = self.c.get("/api/tests", headers={"Authorization": "Bearer " + tok})
        self.assertEqual(r.status_code, 503)

    def test_placeholder_secret_rejected(self):
        """The shipped placeholder value must never act as a real signing key."""
        os.environ["BAYORA_AUTH_SECRET"] = "PLACEHOLDER_SECRET"
        self.addCleanup(os.environ.update, ENV)
        with self.assertRaises(Exception):
            issue_token("a", EVAL)

    def test_token_signed_with_other_secret_rejected(self):
        """A token minted by an attacker with their own key must fail verification."""
        tok = issue_token("a", EVAL)
        os.environ["BAYORA_AUTH_SECRET"] = "a-different-secret-value-0123456789"
        self.addCleanup(os.environ.update, ENV)
        self.assertEqual(self.c.get("/api/tests", headers={"Authorization": "Bearer " + tok}).status_code, 401)

    def test_non_bearer_scheme_rejected(self):
        """Basic/other schemes must not be accepted as credentials."""
        self.assertEqual(self.c.get("/api/tests", headers={"Authorization": "Basic Zm9vOmJhcg=="}).status_code, 401)

    def test_each_token_has_unique_id(self):
        """Unique jti is required so one token can be revoked without affecting others."""
        self.assertNotEqual(verify_token(issue_token("a", RED)).jti, verify_token(issue_token("a", RED)).jti)

    def test_dev_header_auth_off_by_default_and_works_when_enabled(self):
        """Header-role mode is demo-only: off by default (spoof-proof), on only when explicitly enabled."""
        h = {"X-Bayora-Role": "EVALUATOR"}
        self.assertEqual(self.c.get("/api/tests", headers=h).status_code, 401)
        os.environ["BAYORA_DEV_HEADER_AUTH"] = "1"
        self.assertEqual(self.c.get("/api/tests", headers=h).status_code, 200)

    def test_weak_credential_refused_outside_demo_mode(self):
        """Short role credentials are guessable; fail closed unless demo mode is on."""
        os.environ["BAYORA_EVALUATOR_TOKEN"] = "short"
        self.addCleanup(os.environ.update, ENV)
        self.assertEqual(self.c.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "short"}).status_code, 503)
        os.environ["BAYORA_DEV_HEADER_AUTH"] = "1"
        self.assertEqual(self.c.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "short"}).status_code, 200)

    def test_placeholder_credential_refused(self):
        """A leftover PLACEHOLDER credential must not be usable to log in."""
        os.environ["BAYORA_RED_WORKER_TOKEN"] = "PLACEHOLDER_RED_TOKEN_VALUE"
        self.addCleanup(os.environ.update, ENV)
        self.assertEqual(self.c.post("/api/auth/login", json={"role": "RED_TEAM", "credential": "PLACEHOLDER_RED_TOKEN_VALUE"}).status_code, 503)

    def test_login_unknown_role_and_bad_credential(self):
        """Login must not reveal which part failed beyond a generic code, and must reject unknown roles."""
        self.assertEqual(self.c.post("/api/auth/login", json={"role": "ADMIN", "credential": "x"}).status_code, 403)
        self.assertEqual(self.c.post("/api/auth/login", json={"role": "RED_TEAM", "credential": "wrong"}).status_code, 401)

    def test_revoked_token_cannot_be_reused_even_for_logout(self):
        """Revocation is final: a revoked token is dead everywhere."""
        self.assertEqual(self.c.post("/api/auth/logout", headers=self.H[RED]).status_code, 200)
        self.assertEqual(self.c.post("/api/auth/logout", headers=self.H[RED]).status_code, 401)

    def test_logout_is_audited(self):
        """Session ends are part of the accountability trail."""
        self.c.post("/api/auth/logout", headers=self.H[RED])
        evs = self.c.get("/api/audit", headers=self.H[EVAL]).json()["events"]
        self.assertTrue(any(e["action"] == "LOGOUT" for e in evs))

    def test_token_expiry_boundary(self):
        """A token one second past expiry must be rejected; one still valid must pass."""
        self.assertEqual(verify_token(issue_token("a", RED, ttl=5)).role, RED)
        with self.assertRaises(Exception):
            verify_token(issue_token("a", RED, ttl=-1))


# ------------------------------------------------------------------ audit
class TestAudit(Base):
    def test_every_denial_is_audited(self):
        """Accountability: each blocked action must leave a DENY record."""
        tid = self.mk()
        self.step(tid, "close", RED); self.step(tid, "start", BLUE); self.step(tid, "results/release", RED)
        evs = self.c.get(f"/api/audit?test_id={tid}", headers=self.H[EVAL]).json()["events"]
        self.assertGreaterEqual(len([e for e in evs if e["decision"] == "DENY"]), 3)

    def test_empty_chain_is_valid(self):
        """A fresh system must verify cleanly (no false alarms)."""
        db = DatabaseManager(":memory:"); self.addCleanup(db.close)
        self.assertTrue(AuditLogger(db).verify_chain()["valid"])

    def test_deleted_event_detected(self):
        """Deleting a middle record breaks the chain link; must be detected."""
        tid = self.mk(); self.step(tid, "ready"); self.mk("third event source")  # >= 3 events so rowid 2 is a MIDDLE row
        with self.app.db.connection() as conn:
            conn.execute("DELETE FROM audit_events WHERE rowid = 2")
        self.assertFalse(self.c.get("/api/audit/verify", headers=self.H[EVAL]).json()["valid"])

    def test_checkpoint_refused_on_broken_chain(self):
        """Never sign a checkpoint over already-corrupted history."""
        tid = self.mk()
        with self.app.db.connection() as conn:
            conn.execute("UPDATE audit_events SET reason_code = 'X' WHERE rowid = 1")
        self.assertEqual(self.c.get("/api/audit/checkpoint", headers=self.H[EVAL]).status_code, 409)

    def test_checkpoint_signature_depends_on_key(self):
        """A checkpoint must not verify under a different audit key (forgery resistance)."""
        self.mk()
        cp = self.c.get("/api/audit/checkpoint", headers=self.H[EVAL]).json()
        os.environ["BAYORA_AUDIT_KEY"] = "another-audit-key-0123456789"
        self.addCleanup(os.environ.update, ENV)
        r = self.c.post("/api/audit/checkpoint/verify", json=cp, headers=self.H[EVAL]).json()
        self.assertEqual(r["reason"], "BAD_CHECKPOINT_SIGNATURE")

    def test_checkpoint_detects_truncation(self):
        """Deleting the newest events (and fixing nothing else) must be caught by the checkpoint."""
        self.mk(); cp = self.c.get("/api/audit/checkpoint", headers=self.H[EVAL]).json()
        with self.app.db.connection() as conn:
            conn.execute("DELETE FROM audit_events WHERE rowid = (SELECT MAX(rowid) FROM audit_events)")
        r = self.c.post("/api/audit/checkpoint/verify", json=cp, headers=self.H[EVAL]).json()
        self.assertFalse(r["valid"])

    def test_checkpoint_stays_valid_when_new_events_added(self):
        """Normal operation after a checkpoint must not trigger false alarms."""
        self.mk(); cp = self.c.get("/api/audit/checkpoint", headers=self.H[EVAL]).json()
        self.mk("another one")
        r = self.c.post("/api/audit/checkpoint/verify", json=cp, headers=self.H[EVAL]).json()
        self.assertTrue(r["valid"]); self.assertGreater(r["events_since_checkpoint"], 0)

    def test_checkpoint_rejects_wrong_types(self):
        """Malformed checkpoint bodies must be a validation error, not a crash."""
        r = self.c.post("/api/audit/checkpoint/verify", json={"count": "x", "timestamp": "t", "signature": "s"}, headers=self.H[EVAL])
        self.assertEqual(r.status_code, 422)

    def test_event_ids_unique_and_newest_first(self):
        """IDs must not collide (primary key) and timeline must be ordered newest first."""
        for i in range(5):
            self.mk(f"order test {i}")
        evs = self.c.get("/api/audit", headers=self.H[EVAL]).json()["events"]
        ids = [e["id"] for e in evs]
        self.assertEqual(len(ids), len(set(ids)))
        stamps = [e["timestamp"] for e in evs]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_hash_is_sensitive_to_every_field(self):
        """Changing ANY audited field must change the event hash (no unprotected column)."""
        base = ("id", "ts", "t", "r", "a", "role", "act", "res", "ALLOW", "x", "OK")
        h0 = _hash_event("", base)
        for i in range(len(base)):
            changed = list(base); changed[i] = str(changed[i]) + "!"
            self.assertNotEqual(h0, _hash_event("", tuple(changed)), _FIELDS[i])

    def test_chain_survives_restart(self):
        """The chain must continue correctly after the process restarts (file DB reopened)."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "a.db")
        a1 = create_bayora_app(db_path=path); TestClient(a1).post("/api/tests", json={"name": "persisted one"}, headers=self.H[EVAL]); a1.db.close()
        a2 = create_bayora_app(db_path=path); self.addCleanup(a2.db.close)
        c2 = TestClient(a2); c2.post("/api/tests", json={"name": "persisted two"}, headers=self.H[EVAL])
        self.assertTrue(c2.get("/api/audit/verify", headers=self.H[EVAL]).json()["valid"])


# ------------------------------------------------------------------ report
class TestReport(Base):
    def test_report_content_and_honesty_labels(self):
        """The report is what gets presented: it must label mock evidence, include chain status and limitations."""
        tid = self.mk(); self.run_to(tid, "release")
        r = self.c.get(f"/api/tests/{tid}/report", headers=self.H[EVAL]).json()
        self.assertEqual(r["evidence_type"], "MOCK / SIMULATED")
        self.assertTrue(r["audit"]["chain_verification"]["valid"]); self.assertTrue(r["limitations"])

    def test_report_access_is_audited_both_ways(self):
        """Report reads (allowed and denied) are accountable events."""
        tid = self.mk(); self.c.get(f"/api/tests/{tid}/report", headers=self.H[RED])
        self.run_to(tid, "release"); self.c.get(f"/api/tests/{tid}/report", headers=self.H[EVAL])
        evs = [e for e in self.c.get(f"/api/audit?test_id={tid}", headers=self.H[EVAL]).json()["events"] if e["action"] == "GET_TEST_REPORT"]
        self.assertEqual({e["decision"] for e in evs}, {"ALLOW", "DENY"})


# ------------------------------------------------------------------ adapters
def _rows(cats, rules):
    p = [{"id": f"p{i}", "category": c, "severity_tier": "HIGH", "payload_sha256": "a" * 64, "payload_text": "x" * 8} for i, c in enumerate(cats)]
    d = [{"id": f"d{i}", "rule_type": r, "config_sha256": "b" * 64, "defense_config_secret": "s"} for i, r in enumerate(rules)]
    return p, d


class TestAdapters(Base):
    def _mock(self, cats, rules):
        p, d = _rows(cats, rules)
        return DeterministicMockLLMAdapter().evaluate_isolated_run(test_id="t", run_id="run-abcdef12", target_model="m", red_payloads=p, blue_defenses=d)

    def test_mock_is_deterministic(self):
        """Same input -> same verdicts; a 'deterministic' fixture that varies would make regressions undetectable."""
        a, b = self._mock(["PROMPT_INJECTION"] * 3, ["INPUT_SANITIZER"]), self._mock(["PROMPT_INJECTION"] * 3, ["INPUT_SANITIZER"])
        self.assertEqual([o["verdict"] for o in a.probe_outcomes], [o["verdict"] for o in b.probe_outcomes])

    def test_mock_no_defense_everything_bypasses(self):
        """No Blue defense -> nothing blocks; guards against a fail-open 'always blocked' bug."""
        o = self._mock(["PROMPT_INJECTION", "JAILBREAK_ROLEPLAY"], [])
        self.assertEqual((o.blocked_count, o.bypassed_count), (0, 2))

    def test_mock_all_layer_shield_blocks_everything(self):
        """The strongest rule blocks all categories."""
        o = self._mock(["PROMPT_INJECTION", "JAILBREAK_ROLEPLAY", "SYSTEM_PROMPT_EXTRACTION"], ["ALL_LAYER_SHIELD"])
        self.assertEqual(o.resilience_score, 100.0)

    def test_mock_baseline_probe_when_no_payloads(self):
        """With no Red payloads the run still evaluates one baseline probe (no divide-by-zero)."""
        self.assertEqual(self._mock([], ["INPUT_SANITIZER"]).total_probes, 1)

    def test_mock_is_labelled_mock(self):
        """Mock output must always self-identify so it cannot be presented as a real model."""
        o = self._mock(["PROMPT_INJECTION"], []); self.assertTrue(o.is_mock); self.assertIn("MOCK", o.adapter_type)

    def test_gemini_requires_explicit_opt_in(self):
        """Sending secrets to an external API must be a conscious choice, not a default."""
        with self.assertRaises(RuntimeError):
            GeminiAdapter()

    def test_gemini_errors_are_not_counted_as_blocked(self):
        """An API failure is 'no result', never a pass: otherwise outages would inflate resilience."""
        os.environ["BAYORA_ALLOW_EXTERNAL_MODEL"] = "1"; self.addCleanup(os.environ.pop, "BAYORA_ALLOW_EXTERNAL_MODEL", None)

        class Boom(GeminiAdapter):
            def _generate(self, *a): raise OSError("network down")
        p, d = _rows(["PROMPT_INJECTION"], ["SYSTEM_PROMPT_GUARD"])
        o = Boom().evaluate_isolated_run(test_id="t", run_id="r1", target_model="gemini-x", red_payloads=p, blue_defenses=d)
        self.assertEqual(o.blocked_count, 0); self.assertEqual(o.run_status, "COMPLETED_WITH_ERRORS"); self.assertFalse(o.is_mock)

    def test_gemini_records_data_egress(self):
        """Real-model results must disclose that data left the system."""
        os.environ["BAYORA_ALLOW_EXTERNAL_MODEL"] = "1"; self.addCleanup(os.environ.pop, "BAYORA_ALLOW_EXTERNAL_MODEL", None)

        class Ok(GeminiAdapter):
            def _generate(self, *a): return "no"
        p, d = _rows(["PROMPT_INJECTION"], ["SYSTEM_PROMPT_GUARD"])
        o = Ok().evaluate_isolated_run(test_id="t", run_id="r1", target_model="gemini-x", red_payloads=p, blue_defenses=d)
        self.assertIn("data_egress", o.target_config)

    def test_adapter_down_leaves_test_ready(self):
        """If the adapter is unreachable the start must fail AND roll back (no half-started 'Running' test)."""
        os.environ["BAYORA_ADAPTER_URL"] = "http://127.0.0.1:9"; os.environ["BAYORA_ADAPTER_TOKEN"] = "t"
        self.addCleanup(os.environ.pop, "BAYORA_ADAPTER_URL", None)
        app = create_bayora_app(db_path=":memory:"); self.addCleanup(app.db.close); c = TestClient(app)
        tid = c.post("/api/tests", json={"name": "adapter down"}, headers=self.H[EVAL]).json()
        tid = tid.get("test_id") or tid["id"]
        c.post(f"/api/tests/{tid}/ready", headers=self.H[EVAL])
        r = c.post(f"/api/tests/{tid}/start", headers=self.H[EVAL])
        self.assertGreaterEqual(r.status_code, 500)
        self.assertEqual(c.get(f"/api/tests/{tid}/status", headers=self.H[EVAL]).json()["state"], "Ready")


class TestAdapterService(unittest.TestCase):
    def setUp(self):
        os.environ["BAYORA_ADAPTER_TOKEN"] = "svc-token"
        spec = importlib.util.spec_from_file_location("adapter_service_x", ROOT / "workers/target-adapter/adapter_service.py")
        self.svc = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.svc)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), self.svc.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]
        self.addCleanup(lambda: (self.srv.shutdown(), self.srv.server_close()))

    def call(self, method, path, body=None, token="svc-token", raw=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        if token: h["Authorization"] = "Bearer " + token
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse(); r.read(); return r.status

    GOOD = {"test_id": "t", "run_id": "run-aaaaaaaa", "target_model": "m", "red_payloads": [], "blue_defenses": []}

    def test_health_is_public_and_ok(self): self.assertEqual(self.call("GET", "/health", token=None), 200)
    def test_missing_or_wrong_token_is_401(self):
        """Only the control plane (holding the token) may run evaluations."""
        self.assertEqual(self.call("POST", "/evaluate", self.GOOD, token=None), 401)
        self.assertEqual(self.call("POST", "/evaluate", self.GOOD, token="nope"), 401)
    def test_good_request_is_200(self): self.assertEqual(self.call("POST", "/evaluate", self.GOOD), 200)
    def test_missing_fields_and_bad_json_are_400(self):
        """Malformed input must be a clean 400, never a crash that leaks internals."""
        self.assertEqual(self.call("POST", "/evaluate", {"test_id": "t"}), 400)
        self.assertEqual(self.call("POST", "/evaluate", raw=b"{not-json", headers={"Content-Length": "9"}), 400)
    def test_oversized_body_is_413(self):
        """Large bodies must be refused before being read (memory DoS)."""
        self.assertEqual(self.call("POST", "/evaluate", raw=b"x", headers={"Content-Length": str(self.svc.MAX_BODY + 1)}), 413)
    def test_unknown_paths_are_404(self):
        self.assertEqual(self.call("GET", "/nope", token=None), 404); self.assertEqual(self.call("POST", "/other", self.GOOD), 404)
    def test_slow_target_returns_504(self):
        """A hung model must produce a bounded timeout, not hang the service."""
        class Slow:
            def evaluate_isolated_run(self, **k): time.sleep(0.6)
        self.svc.get_adapter = lambda: Slow(); self.svc.TIMEOUT_S = 0.1
        self.assertEqual(self.call("POST", "/evaluate", self.GOOD), 504)
    def test_target_crash_returns_502_without_details(self):
        """Adapter exceptions must map to a generic 502 (no stack traces)."""
        class Crash:
            def evaluate_isolated_run(self, **k): raise ValueError("secret internals")
        self.svc.get_adapter = lambda: Crash()
        self.assertEqual(self.call("POST", "/evaluate", self.GOOD), 502)


# ------------------------------------------------------------------ concurrency
class TestConcurrency(Base):
    def test_parallel_start_runs_exactly_once(self):
        """Race condition guard: two simultaneous 'start' calls must not both succeed (double evaluation)."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        app = create_bayora_app(db_path=os.path.join(d, "c.db")); c = TestClient(app)
        t = c.post("/api/tests", json={"name": "race test"}, headers=self.H[EVAL]).json(); tid = t.get("test_id") or t["id"]
        c.post(f"/api/tests/{tid}/ready", headers=self.H[EVAL])
        codes = []
        ts = [threading.Thread(target=lambda: codes.append(c.post(f"/api/tests/{tid}/start", headers=self.H[EVAL]).status_code)) for _ in range(6)]
        [x.start() for x in ts]; [x.join() for x in ts]
        self.assertEqual(codes.count(200), 1, codes)
        with app.db.connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) c FROM evaluation_results WHERE test_id = ?", (tid,)).fetchone()["c"], 1)
        app.db.close()


# ------------------------------------------------------------------ HTTP layer
class TestHttpLayer(Base):
    port = 18340

    @classmethod
    def setUpClass(cls):
        for k in CLEAR: os.environ.pop(k, None)
        os.environ.update(ENV)
        cls.app = create_bayora_app(db_path=":memory:")
        threading.Thread(target=compat.run_http_server, args=(cls.app, "127.0.0.1", cls.port), daemon=True).start()
        for _ in range(50):
            try: http.client.HTTPConnection("127.0.0.1", cls.port, timeout=1).connect(); break
            except OSError: time.sleep(0.1)

    @classmethod
    def tearDownClass(cls): cls.app.db.close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse(); data = r.read(); return r, data

    def test_malformed_json_is_4xx(self):
        """Garbage bodies must not produce 500s."""
        r, _ = self.req("POST", "/api/auth/login", b"{not json", {"Content-Type": "application/json", "Content-Length": "9"})
        self.assertTrue(400 <= r.status < 500, r.status)

    def test_non_numeric_content_length_is_rejected(self):
        """A bogus Content-Length used to crash the handler thread."""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest("POST", "/api/auth/login"); c.putheader("Content-Length", "abc"); c.endheaders()
        self.assertEqual(c.getresponse().status, 413)

    def test_security_headers_on_success_and_error(self):
        """Hardening headers must be present on every response, including errors."""
        for path in ("/api/health", "/api/tests"):
            r, _ = self.req("GET", path)
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff", path)
            self.assertEqual(r.getheader("Cache-Control"), "no-store", path)

    def test_cors_enabled_only_for_configured_origin(self):
        """CORS must be opt-in for ONE origin and never '*'."""
        r, _ = self.req("GET", "/api/health"); self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))
        os.environ["BAYORA_CORS_ORIGIN"] = "https://app.example"; self.addCleanup(os.environ.pop, "BAYORA_CORS_ORIGIN", None)
        r, _ = self.req("GET", "/api/health"); self.assertEqual(r.getheader("Access-Control-Allow-Origin"), "https://app.example")
        os.environ["BAYORA_CORS_ORIGIN"] = "*"
        r, _ = self.req("GET", "/api/health"); self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))

    def test_errors_do_not_leak_internals(self):
        """No Python tracebacks or file paths in error bodies."""
        _, data = self.req("GET", "/api/tests/xyz/status")
        self.assertNotIn(b"Traceback", data); self.assertNotIn(b".py", data)

    def test_health_reports_mock_honestly(self):
        """The health endpoint is the first thing people see; it must say mock when it is mock."""
        _, data = self.req("GET", "/api/health"); j = json.loads(data)
        self.assertTrue(j["target_adapter"]["is_mock"])


# ------------------------------------------------------------------ database
class TestDatabase(unittest.TestCase):
    def test_file_permissions_are_owner_only(self):
        """The DB holds audit evidence and defense secrets hashes; other OS users must not read it."""
        if os.name == "nt": self.skipTest("POSIX permissions only")
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "x.db"); DatabaseManager(p).close()
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_old_schema_is_migrated(self):
        """Existing databases from before the hash chain must upgrade in place, not crash."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "old.db"); c = sqlite3.connect(p)
        c.execute("CREATE TABLE audit_events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, test_id TEXT NOT NULL, run_id TEXT, actor TEXT NOT NULL, role TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL, decision TEXT NOT NULL, state_transition TEXT, reason_code TEXT NOT NULL)")
        c.commit(); c.close()
        db = DatabaseManager(p)
        with db.connection() as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)")}
        db.close(); self.assertTrue({"prev_hash", "event_hash"} <= cols)

    def test_close_is_idempotent(self):
        """Shutdown hooks may run twice; closing twice must not raise."""
        db = DatabaseManager(":memory:"); db.close(); db.close()


# ------------------------------------------------------------------ deployment configuration (static)
class TestDeploymentConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose_text = (ROOT / "compose.yaml").read_text()
        try:
            import yaml
            cls.compose = yaml.safe_load(cls.compose_text)
        except ImportError:
            cls.compose = None

    def need_yaml(self):
        if self.compose is None: self.skipTest("PyYAML not installed")

    def nets(self, svc):
        n = self.compose["services"][svc].get("networks", [])
        return sorted(n if isinstance(n, list) else n.keys())

    def test_red_and_blue_share_no_network(self):
        """Core isolation claim: Red and Blue workers must not be on any common network."""
        self.need_yaml()
        self.assertEqual(self.nets("red-worker"), ["red-net"]); self.assertEqual(self.nets("blue-worker"), ["blue-net"])

    def test_team_networks_are_internal_and_control_is_not_needed_by_workers(self):
        """internal:true removes internet egress for Red/Blue; target adapter reachable only on control-net."""
        self.need_yaml()
        nets = self.compose["networks"]
        self.assertTrue(nets["red-net"]["internal"]); self.assertTrue(nets["blue-net"]["internal"])
        self.assertEqual(self.nets("target-adapter"), ["control-net"])
        self.assertEqual(self.nets("control-plane"), ["blue-net", "control-net", "red-net"])

    def test_backend_not_published_to_host(self):
        """Backend must be reachable only through the gateway (no direct host port)."""
        self.need_yaml(); self.assertNotIn("ports", self.compose["services"]["control-plane"])

    def test_all_services_hardened_and_non_root(self):
        """Least privilege for every container."""
        self.need_yaml()
        for name, svc in self.compose["services"].items():
            self.assertEqual(svc["cap_drop"], ["ALL"], name)
            self.assertIn("no-new-privileges:true", svc["security_opt"], name)
            self.assertNotIn(str(svc["user"]).split(":")[0], ("0", "root"), name)

    def test_no_placeholder_secret_defaults(self):
        """A forgotten .env must fail startup, not silently run with a known secret."""
        self.assertNotIn("PLACEHOLDER", self.compose_text)
        self.assertIn(":?set", self.compose_text)

    def test_referenced_dockerfiles_exist_and_drop_root(self):
        """The original archive was missing three Dockerfiles; each must exist and end non-root."""
        for df in re.findall(r"dockerfile:\s*(\S+)", self.compose_text):
            p = ROOT / df; self.assertTrue(p.exists(), df)
            users = re.findall(r"^USER\s+(\S+)", p.read_text(), re.M)
            self.assertTrue(users and not users[-1].startswith(("0", "root")), df)

    def test_dockerignore_excludes_env_secrets(self):
        """COPY . would otherwise bake .env (all secrets) into images."""
        self.assertIn(".env", (ROOT / ".dockerignore").read_text().splitlines())

    def test_env_example_contains_no_real_secrets(self):
        """The example file ships in the repo; secret slots must be empty."""
        txt = (ROOT / ".env.example").read_text()
        for k in ("AUTH_SECRET", "RED_WORKER_TOKEN", "BLUE_WORKER_TOKEN", "EVALUATOR_TOKEN", "ADAPTER_TOKEN"):
            self.assertRegex(txt, rf"(?m)^BAYORA_{k}=\s*$")
        self.assertRegex(txt, r"(?m)^BAYORA_ALLOW_EXTERNAL_MODEL=0")

    def test_isolation_script_has_valid_bash_syntax(self):
        """The runtime isolation proof must at least parse."""
        if not shutil.which("bash"): self.skipTest("bash not available")
        self.assertEqual(subprocess.run(["bash", "-n", str(ROOT / "scripts/verify_isolation.sh")]).returncode, 0)

    def test_express_version_matches_route_syntax(self):
        """'/api/*splat' is Express 5 syntax; Express 4 would crash at startup."""
        self.assertIn('"express": "^5', (ROOT / "package.json").read_text())

    def test_gateway_never_forwards_browser_role_headers(self):
        """The gateway must not pass X-Bayora-Role through to the backend."""
        ts = (ROOT / "server.ts").read_text()
        self.assertNotIn("forwardHeaders['X-Bayora-Role']", ts)

    def test_backend_requirements_have_no_unused_frameworks(self):
        """requirements.txt once listed FastAPI/uvicorn that the code never imported."""
        req = (ROOT / "backend/requirements.txt").read_text().lower()
        for pkg in ("fastapi", "uvicorn", "pydantic"): self.assertNotIn(pkg, req)


if __name__ == "__main__":
    unittest.main()
