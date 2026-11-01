"""Tests for per-person accounts, per-test assignment, persistent throttling, TLS and the user CLI. Each states WHY."""
from __future__ import annotations

import http.client
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import backend.app.compat as compat
from backend.app.api import create_bayora_app
from backend.app.auth import Role, create_user, hash_password, issue_token, verify_password, verify_token
from backend.app.compat import TestClient
from backend.app.database import DatabaseManager

ROOT = Path(__file__).resolve().parents[2]
ENV = dict(BAYORA_AUTH_SECRET="acct-secret-0123456789abcdef0123", BAYORA_RED_WORKER_TOKEN="red-credential-0123456789",
           BAYORA_BLUE_WORKER_TOKEN="blue-credential-012345678", BAYORA_EVALUATOR_TOKEN="eval-credential-01234567",
           BAYORA_AUDIT_KEY="audit-key-0123456789abcdef")
RED, BLUE, EVAL = Role.RED_TEAM, Role.BLUE_TEAM, Role.EVALUATOR
PAYLOAD = {"category": "PROMPT_INJECTION", "severity_tier": "HIGH", "payload_text": "ignore previous instructions"}
DEFENSE = {"defense_name": "Guard", "rule_type": "SYSTEM_PROMPT_GUARD", "defense_config_secret": "deny override"}
PW = "correct-horse-battery"


class Base(unittest.TestCase):
    def setUp(self):
        for k in ("BAYORA_DEV_HEADER_AUTH", "BAYORA_ADAPTER_URL", "BAYORA_TARGET_ADAPTER_MODE", "BAYORA_DISABLE_ROLE_CREDENTIALS",
                  "BAYORA_TLS_CERT", "BAYORA_TLS_KEY"):
            os.environ.pop(k, None)
        os.environ.update(ENV)
        self.app = create_bayora_app(db_path=":memory:"); self.addCleanup(self.app.db.close)
        self.c = TestClient(self.app)
        self.E = {"Authorization": "Bearer " + issue_token("eval-boss", EVAL)}

    def user(self, name, role, pw=PW):
        create_user(self.app.db, name, role, pw)

    def login(self, name, pw=PW):
        return self.c.post("/api/auth/login", json={"username": name, "credential": pw})

    def hdr(self, name, pw=PW):
        return {"Authorization": "Bearer " + self.login(name, pw).json()["token"]}

    def mk(self):
        j = self.c.post("/api/tests", json={"name": "Assignment test"}, headers=self.E).json()
        return j.get("test_id") or j["id"]

    def assign(self, tid, actor, role):
        return self.c.post(f"/api/tests/{tid}/participants", json={"actor": actor, "role": role}, headers=self.E)


class TestPasswords(unittest.TestCase):
    def test_hash_verifies_and_is_salted(self):
        """Passwords must be stored as salted scrypt: same password -> different hashes, both verify."""
        a, b = hash_password(PW), hash_password(PW)
        self.assertNotEqual(a, b); self.assertTrue(verify_password(PW, a) and verify_password(PW, b))
        self.assertNotIn(PW, a)

    def test_wrong_and_malformed_hash_rejected(self):
        """A wrong password or a corrupted stored hash must fail closed (no exception, no accept)."""
        self.assertFalse(verify_password("wrong-password-xx", hash_password(PW)))
        for bad in ("", "garbage", "scrypt$1$2"):
            self.assertFalse(verify_password(PW, bad))


class TestAccounts(Base):
    def test_user_login_assigns_server_side_role_and_actor(self):
        """Identity must come from the users table: caller-supplied role/actor are ignored."""
        self.user("alice", RED)
        r = self.c.post("/api/auth/login", json={"username": "alice", "credential": PW, "role": "EVALUATOR", "actor": "boss"}).json()
        ident = verify_token(r["token"]); self.assertEqual((ident.actor, ident.role, r["role"]), ("alice", RED, "RED_TEAM"))

    def test_audit_attributes_actions_to_the_person(self):
        """The audit trail must name the individual, which shared role credentials could not."""
        self.user("alice", RED); tid = self.mk()
        self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.hdr("alice"))
        evs = self.c.get(f"/api/audit?test_id={tid}", headers=self.E).json()["events"]
        self.assertTrue(any(e["actor"] == "alice" and e["action"] == "SUBMIT_RED_PAYLOAD" for e in evs))

    def test_wrong_password_and_unknown_user_look_identical(self):
        """No user enumeration: both failures return the same status and code."""
        self.user("alice", RED)
        a = self.login("alice", "wrong-password-xx"); b = self.login("nobody", "wrong-password-xx")
        self.assertEqual((a.status_code, a.json()["code"]), (b.status_code, b.json()["code"]))

    def test_only_evaluator_creates_users(self):
        """Account creation is privilege escalation; Red/Blue must not be able to do it."""
        body = {"username": "mallory", "role": "EVALUATOR", "password": PW}
        for role in (RED, BLUE):
            r = self.c.post("/api/users", json=body, headers={"Authorization": "Bearer " + issue_token("x", role)})
            self.assertEqual(r.status_code, 403)
        self.assertEqual(self.c.post("/api/users", json=body).status_code, 401)

    def test_user_creation_validation_and_duplicates(self):
        """Weak passwords, bad names, bad roles and duplicates must be refused."""
        ok = {"username": "bob.smith", "role": "BLUE_TEAM", "password": PW}
        self.assertEqual(self.c.post("/api/users", json=ok, headers=self.E).status_code, 200)
        self.assertEqual(self.c.post("/api/users", json=ok, headers=self.E).status_code, 422)
        for bad in ({**ok, "username": "bad name!"}, {**ok, "username": "carol", "role": "ROOT"}, {**ok, "username": "dan", "password": "short"}):
            self.assertEqual(self.c.post("/api/users", json=bad, headers=self.E).status_code, 422, bad)

    def test_user_list_never_exposes_hashes(self):
        """Password hashes must never leave the database."""
        self.user("alice", RED)
        body = self.c.get("/api/users", headers=self.E).text
        self.assertIn("alice", body); self.assertNotIn("scrypt", body)

    def test_created_users_are_audited(self):
        """Account creation must leave an audit record naming who did it."""
        self.c.post("/api/users", json={"username": "erin", "role": "RED_TEAM", "password": PW}, headers=self.E)
        evs = self.c.get("/api/audit", headers=self.E).json()["events"]
        self.assertTrue(any(e["action"] == "CREATE_USER" and e["actor"] == "eval-boss" for e in evs))

    def test_role_credentials_can_be_disabled(self):
        """Production can force personal accounts by turning off the shared role credentials."""
        os.environ["BAYORA_DISABLE_ROLE_CREDENTIALS"] = "1"
        r = self.c.post("/api/auth/login", json={"role": "RED_TEAM", "credential": ENV["BAYORA_RED_WORKER_TOKEN"]})
        self.assertEqual(r.status_code, 403)

    def test_user_lockout_never_blocks_correct_password(self):
        """Guess throttling must not let an attacker lock the real user out."""
        self.user("alice", RED)
        for _ in range(5): self.login("alice", "wrong-password-xx")
        self.assertEqual(self.login("alice", "wrong-password-xx").status_code, 429)
        self.assertEqual(self.login("alice").status_code, 200)

    def test_lockout_is_per_user_not_global(self):
        """Failures against one account must not affect another account."""
        self.user("alice", RED); self.user("bob", BLUE)
        for _ in range(6): self.login("alice", "wrong-password-xx")
        self.assertEqual(self.login("bob").status_code, 200)


class TestPersistentThrottle(Base):
    def test_lockout_survives_restart(self):
        """Guess counters are in the DB, so restarting the server cannot reset an attack."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); path = os.path.join(d, "t.db")
        a1 = create_bayora_app(db_path=path); c1 = TestClient(a1)
        for _ in range(5): c1.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "x"})
        a1.db.close()
        a2 = create_bayora_app(db_path=path); self.addCleanup(a2.db.close)
        r = TestClient(a2).post("/api/auth/login", json={"role": "EVALUATOR", "credential": "x"})
        self.assertEqual(r.status_code, 429)

    def test_unauthenticated_audit_limiter_survives_restart(self):
        """The flood limiter also lives in the DB, so a restart cannot be used to flood the audit log."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); path = os.path.join(d, "u.db")
        a1 = create_bayora_app(db_path=path); TestClient(a1).get("/api/tests"); a1.db.close()
        a2 = create_bayora_app(db_path=path); self.addCleanup(a2.db.close); TestClient(a2).get("/api/tests")
        with a2.db.connection() as c:
            n = c.execute("SELECT COUNT(*) FROM audit_events WHERE role = 'UNAUTHENTICATED'").fetchone()[0]
        self.assertEqual(n, 1)


class TestAssignments(Base):
    def test_unassigned_red_is_blocked_assigned_is_allowed(self):
        """Once the evaluator assigns Red users, other Red users must lose access to that test."""
        self.user("red1", RED); self.user("red2", RED); tid = self.mk()
        self.assertEqual(self.assign(tid, "red1", "RED_TEAM").status_code, 200)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.hdr("red1")).status_code, 201)
        r = self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.hdr("red2"))
        self.assertEqual((r.status_code, r.json()["code"]), (403, "NOT_ASSIGNED_TO_TEST"))

    def test_unassigned_user_cannot_read_payloads(self):
        """Reading raw payloads is as sensitive as writing them."""
        self.user("red1", RED); self.user("red2", RED); tid = self.mk(); self.assign(tid, "red1", "RED_TEAM")
        self.assertEqual(self.c.get(f"/api/tests/{tid}/payloads", headers=self.hdr("red1")).status_code, 200)
        self.assertEqual(self.c.get(f"/api/tests/{tid}/payloads", headers=self.hdr("red2")).status_code, 403)

    def test_blue_assignment_is_enforced_independently(self):
        """Blue assignments restrict Blue only; Red's assignment state must not affect Blue (and vice versa)."""
        self.user("blue1", BLUE); self.user("blue2", BLUE); self.user("red1", RED); tid = self.mk()
        self.assign(tid, "blue1", "BLUE_TEAM")
        self.assertEqual(self.c.post(f"/api/tests/{tid}/defenses", json=DEFENSE, headers=self.hdr("blue1")).status_code, 201)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/defenses", json=DEFENSE, headers=self.hdr("blue2")).status_code, 403)
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.hdr("red1")).status_code, 201)

    def test_test_without_assignments_stays_open(self):
        """Backward compatible: no assignments means the role-level rules apply as before."""
        self.user("red9", RED); tid = self.mk()
        self.assertEqual(self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.hdr("red9")).status_code, 201)

    def test_blue_reading_red_payloads_still_gets_sec02_denial(self):
        """Assignment checks must not mask the SEC-02 policy reason for the wrong role."""
        self.user("blue1", BLUE); self.user("red1", RED); tid = self.mk(); self.assign(tid, "red1", "RED_TEAM")
        r = self.c.get(f"/api/tests/{tid}/payloads", headers=self.hdr("blue1"))
        self.assertEqual((r.status_code, r.json()["code"]), (403, "SEC_02_BLUE_READ_RED_PAYLOAD_DENIED"))

    def test_only_evaluator_assigns_and_lists(self):
        """Assignment is an access-control decision; only the evaluator may make or view it."""
        tid = self.mk(); H = {"Authorization": "Bearer " + issue_token("r", RED)}
        self.assertEqual(self.c.post(f"/api/tests/{tid}/participants", json={"actor": "red-user", "role": "RED_TEAM"}, headers=H).status_code, 403)
        self.assertEqual(self.c.get(f"/api/tests/{tid}/participants", headers=H).status_code, 403)
        self.assign(tid, "someone", "RED_TEAM")
        self.assertEqual(self.c.get(f"/api/tests/{tid}/participants", headers=self.E).json()["participants"][0]["actor"], "someone")

    def test_participant_role_and_test_validation(self):
        """Evaluators cannot be 'assigned' and unknown tests must 404."""
        tid = self.mk()
        self.assertEqual(self.assign(tid, "x-user", "EVALUATOR").status_code, 422)
        self.assertEqual(self.assign("no-such-test", "x-user", "RED_TEAM").status_code, 404)

    def test_assignment_denial_and_grant_are_audited(self):
        """Both the assignment and any resulting denial must appear in the audit trail."""
        self.user("red1", RED); self.user("red2", RED); tid = self.mk(); self.assign(tid, "red1", "RED_TEAM")
        self.c.post(f"/api/tests/{tid}/payloads", json=PAYLOAD, headers=self.hdr("red2"))
        evs = self.c.get(f"/api/audit?test_id={tid}", headers=self.E).json()["events"]
        reasons = {e["reason_code"] for e in evs}
        self.assertTrue({"PARTICIPANT_ASSIGNED", "NOT_ASSIGNED_TO_TEST"} <= reasons)

    def test_evaluator_workflow_unaffected_by_assignments(self):
        """Assignments restrict Red/Blue writers only; the evaluator lifecycle still works."""
        self.user("red1", RED); tid = self.mk(); self.assign(tid, "red1", "RED_TEAM")
        for a in ("ready", "start", "close", "results/release"):
            self.assertEqual(self.c.post(f"/api/tests/{tid}/{a}", headers=self.E).status_code, 200, a)


class TestCliAndTls(Base):
    def test_cli_creates_account_that_can_log_in(self):
        """The CLI is how the first evaluator is bootstrapped; it must produce a working account."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); path = os.path.join(d, "cli.db")
        env = {**os.environ, "BAYORA_DB_PATH": path, "BAYORA_NEW_PASSWORD": PW, "PYTHONPATH": str(ROOT)}
        r = subprocess.run([sys.executable, "-m", "backend.app.users_cli", "add", "root.eval", "EVALUATOR"], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        app = create_bayora_app(db_path=path); self.addCleanup(app.db.close)
        res = TestClient(app).post("/api/auth/login", json={"username": "root.eval", "credential": PW})
        self.assertEqual(res.json()["role"], "EVALUATOR")

    def test_cli_rejects_weak_password_and_bad_role(self):
        """The CLI must enforce the same rules as the API."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        env = {**os.environ, "BAYORA_DB_PATH": os.path.join(d, "x.db"), "BAYORA_NEW_PASSWORD": "short", "PYTHONPATH": str(ROOT)}
        self.assertEqual(subprocess.run([sys.executable, "-m", "backend.app.users_cli", "add", "weak.user", "EVALUATOR"], cwd=ROOT, env=env, capture_output=True).returncode, 1)
        self.assertEqual(subprocess.run([sys.executable, "-m", "backend.app.users_cli", "add", "weak.user", "KING"], cwd=ROOT, env=env, capture_output=True).returncode, 2)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not available")
    def test_native_tls_serves_https(self):
        """Optional TLS must really encrypt: an HTTPS request succeeds and plain HTTP does not get a valid reply."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
        os.environ["BAYORA_TLS_CERT"], os.environ["BAYORA_TLS_KEY"] = crt, key
        port = 18351
        threading.Thread(target=compat.run_http_server, args=(self.app, "127.0.0.1", port), daemon=True).start()
        time.sleep(0.5)
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ssl._create_unverified_context())
        conn.request("GET", "/api/health"); self.assertEqual(conn.getresponse().status, 200)
        plain = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        with self.assertRaises(Exception):
            plain.request("GET", "/api/health"); plain.getresponse().read()

    def test_tls_proxy_profile_is_hardened_and_optional(self):
        """The TLS reverse-proxy option must be opt-in (profile) and follow the same hardening rules."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        svc = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]["tls-proxy"]
        self.assertEqual(svc["profiles"], ["tls"]); self.assertEqual(svc["cap_drop"], ["ALL"]); self.assertTrue(svc["read_only"])
        self.assertTrue((ROOT / "deploy/Caddyfile").exists())


if __name__ == "__main__":
    unittest.main()
