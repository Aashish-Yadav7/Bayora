"""Tests for MFA (TOTP), password change/reset, account disable, session supersession, list filtering and
static checks of the cookie-session/CSRF/login-dialog frontend changes. Each test states WHY."""
from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import shutil
import unittest
from pathlib import Path

from backend.app.api import create_bayora_app
from backend.app.auth import (Role, create_user, ensure_tables, issue_token, new_totp_secret, totp_at, verify_totp)
from backend.app.compat import TestClient
from backend.app.database import DatabaseManager

ROOT = Path(__file__).resolve().parents[2]
ENV = dict(BAYORA_AUTH_SECRET="hard-secret-0123456789abcdef0123", BAYORA_RED_WORKER_TOKEN="red-credential-0123456789",
           BAYORA_BLUE_WORKER_TOKEN="blue-credential-012345678", BAYORA_EVALUATOR_TOKEN="eval-credential-01234567",
           BAYORA_AUDIT_KEY="audit-key-0123456789abcdef")
RED, BLUE, EVAL = Role.RED_TEAM, Role.BLUE_TEAM, Role.EVALUATOR
PW, PW2 = "correct-horse-battery", "another-long-password-9"


class Base(unittest.TestCase):
    def setUp(self):
        for k in ("BAYORA_DEV_HEADER_AUTH", "BAYORA_ADAPTER_URL", "BAYORA_DISABLE_ROLE_CREDENTIALS"):
            os.environ.pop(k, None)
        os.environ.update(ENV)
        self.app = create_bayora_app(db_path=":memory:"); self.addCleanup(self.app.db.close)
        self.c = TestClient(self.app)
        create_user(self.app.db, "boss", EVAL, PW)
        self.E = self.hdr("boss")

    def login(self, name, pw=PW, otp=""):
        return self.c.post("/api/auth/login", json={"username": name, "credential": pw, "otp": otp})

    def hdr(self, name, pw=PW, otp=""):
        r = self.login(name, pw, otp); self.assertEqual(r.status_code, 200, r.json())
        return {"Authorization": "Bearer " + r.json()["token"]}

    def mk_user(self, name, role=RED, pw=PW):
        create_user(self.app.db, name, role, pw)


class TestTotp(unittest.TestCase):
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # ASCII "12345678901234567890"

    def test_matches_rfc6238_vectors(self):
        """Our TOTP must match the standard's published vectors, or real authenticator apps would never work."""
        self.assertEqual(totp_at(self.SECRET, 59), "287082")
        self.assertEqual(totp_at(self.SECRET, 1111111109), "081804")
        self.assertEqual(totp_at(self.SECRET, 20000000000), "353130")

    def test_window_and_replay_protection(self):
        """+-30 s drift is accepted; a used code is never accepted twice; far-off codes fail."""
        t = 1111111109
        c = verify_totp(self.SECRET, totp_at(self.SECRET, t), t=t); self.assertIsNotNone(c)
        self.assertIsNone(verify_totp(self.SECRET, totp_at(self.SECRET, t), last_used=c, t=t))
        self.assertIsNotNone(verify_totp(self.SECRET, totp_at(self.SECRET, t - 30), t=t))
        self.assertIsNone(verify_totp(self.SECRET, totp_at(self.SECRET, t - 300), t=t))
        self.assertIsNone(verify_totp(self.SECRET, "", t=t))

    def test_new_secrets_are_random_base32(self):
        """Secrets must be unique and valid base32 (160 bits)."""
        a, b = new_totp_secret(), new_totp_secret()
        self.assertNotEqual(a, b); self.assertRegex(a, r"^[A-Z2-7]{32}$")


class TestMfaFlow(Base):
    def enroll(self, name="alice"):
        self.mk_user(name); h = self.hdr(name)
        secret = self.c.post("/api/auth/mfa/enroll", headers=h).json()["secret"]
        self.assertEqual(self.c.post("/api/auth/mfa/confirm", json={"code": totp_at(secret)}, headers=h).status_code, 200)
        return secret

    def test_enrolment_is_inactive_until_confirmed(self):
        """A typo during setup must not lock the user out: MFA only turns on after a valid code."""
        self.mk_user("alice"); h = self.hdr("alice")
        self.c.post("/api/auth/mfa/enroll", headers=h)
        self.assertEqual(self.c.post("/api/auth/mfa/confirm", json={"code": "000000"}, headers=h).status_code, 401)
        self.assertEqual(self.login("alice").status_code, 200)  # still password-only

    def test_login_requires_and_validates_otp(self):
        """With MFA on, a stolen password alone must not be enough."""
        secret = self.enroll()
        r = self.login("alice"); self.assertEqual((r.status_code, r.json()["code"]), (401, "AUTH_OTP_REQUIRED"))
        self.assertEqual(self.login("alice", otp="123456").status_code, 401)
        with self.app.db.connection() as conn:  # confirmation used this 30 s window; rewind instead of sleeping
            conn.execute("UPDATE users SET totp_last = 0 WHERE username = 'alice'")
        self.assertEqual(self.login("alice", otp=totp_at(secret)).status_code, 200)

    def test_used_code_cannot_be_replayed(self):
        """An intercepted one-time code must be useless after first use."""
        secret = self.enroll()
        # confirmation consumed the current counter; the same code must be refused at login
        self.assertEqual(self.login("alice", otp=totp_at(secret)).status_code, 401)

    def test_otp_guessing_is_throttled_even_with_correct_password(self):
        """Attackers who know the password must not be able to brute-force the 6-digit code."""
        secret = self.enroll()
        for _ in range(5): self.login("alice", otp="111111")
        self.assertEqual(self.login("alice", otp="222222").status_code, 429)

    def test_evaluator_can_reset_mfa(self):
        """Lost-phone recovery path: evaluator removes MFA and the user can sign in with the password again."""
        self.enroll()
        self.assertEqual(self.c.post("/api/users/alice/mfa/reset", headers=self.E).status_code, 200)
        self.assertEqual(self.login("alice").status_code, 200)

    def test_role_credential_sessions_cannot_enrol(self):
        """MFA belongs to personal accounts; shared role tokens must be refused cleanly."""
        h = {"Authorization": "Bearer " + issue_token("red_team-operator", RED)}
        self.assertEqual(self.c.post("/api/auth/mfa/enroll", headers=h).status_code, 400)

    def test_mfa_events_are_audited(self):
        """Security-relevant account changes must be in the audit trail."""
        self.enroll()
        reasons = {e["reason_code"] for e in self.c.get("/api/audit", headers=self.E).json()["events"]}
        self.assertTrue({"MFA_ENROLL_STARTED", "MFA_ENABLED"} <= reasons)


class TestPasswords(Base):
    def test_change_password_ends_old_sessions(self):
        """After a password change every earlier token (possibly stolen) must stop working."""
        self.mk_user("alice"); old = self.hdr("alice")
        r = self.c.post("/api/auth/password", json={"current_password": PW, "new_password": PW2}, headers=old)
        self.assertEqual(r.status_code, 200)
        r = self.c.get("/api/tests", headers=old); self.assertEqual((r.status_code, r.json()["code"]), (401, "AUTH_TOKEN_SUPERSEDED"))
        self.assertEqual(self.login("alice", PW).status_code, 401)
        self.assertEqual(self.c.get("/api/tests", headers=self.hdr("alice", PW2)).status_code, 200)

    def test_wrong_current_password_and_throttle(self):
        """Changing a password needs the current one, and guesses are throttled."""
        self.mk_user("alice"); h = self.hdr("alice"); body = {"current_password": "nope-nope-nope", "new_password": PW2}
        for _ in range(5): self.assertEqual(self.c.post("/api/auth/password", json=body, headers=h).status_code, 401)
        self.assertEqual(self.c.post("/api/auth/password", json=body, headers=h).status_code, 429)

    def test_short_new_password_rejected(self):
        """New passwords obey the same minimum length as new accounts."""
        self.mk_user("alice"); h = self.hdr("alice")
        self.assertEqual(self.c.post("/api/auth/password", json={"current_password": PW, "new_password": "short"}, headers=h).status_code, 422)

    def test_role_token_cannot_change_password(self):
        """Shared-role sessions have no password to change."""
        h = {"Authorization": "Bearer " + issue_token("red_team-operator", RED)}
        self.assertEqual(self.c.post("/api/auth/password", json={"current_password": PW, "new_password": PW2}, headers=h).status_code, 400)

    def test_evaluator_reset_invalidates_sessions_and_is_evaluator_only(self):
        """Admin reset must kill the old sessions; non-evaluators must not be able to do it."""
        self.mk_user("alice"); old = self.hdr("alice")
        self.assertEqual(self.c.post("/api/users/alice/reset-password", json={"new_password": PW2}, headers=old).status_code, 403)
        self.assertEqual(self.c.post("/api/users/alice/reset-password", json={"new_password": PW2}, headers=self.E).status_code, 200)
        self.assertEqual(self.c.get("/api/tests", headers=old).status_code, 401)
        self.assertEqual(self.login("alice", PW2).status_code, 200)
        self.assertEqual(self.c.post("/api/users/ghost/reset-password", json={"new_password": PW2}, headers=self.E).status_code, 404)

    def test_password_events_audited_without_passwords(self):
        """Audit must record that a change happened, never the password itself."""
        self.mk_user("alice"); h = self.hdr("alice")
        self.c.post("/api/auth/password", json={"current_password": PW, "new_password": PW2}, headers=h)
        body = self.c.get("/api/audit", headers=self.E).text
        self.assertIn("PASSWORD_CHANGED", body); self.assertNotIn(PW2, body); self.assertNotIn(PW, body)


class TestDisable(Base):
    def test_disabled_user_cannot_log_in_or_use_existing_token(self):
        """Offboarding: disabling must work immediately, including for tokens already issued."""
        self.mk_user("alice"); h = self.hdr("alice")
        self.assertEqual(self.c.post("/api/users/alice/disable", headers=self.E).status_code, 200)
        self.assertEqual(self.c.get("/api/tests", headers=h).status_code, 401)
        self.assertEqual(self.login("alice").status_code, 401)

    def test_enable_restores_access(self):
        """Disable must be reversible."""
        self.mk_user("alice"); self.c.post("/api/users/alice/disable", headers=self.E)
        self.c.post("/api/users/alice/enable", headers=self.E)
        self.assertEqual(self.login("alice").status_code, 200)

    def test_cannot_disable_self_or_unknown_and_evaluator_only(self):
        """Prevent lock-out of the last admin and privilege misuse."""
        self.assertEqual(self.c.post("/api/users/boss/disable", headers=self.E).status_code, 422)
        self.assertEqual(self.c.post("/api/users/ghost/disable", headers=self.E).status_code, 404)
        self.mk_user("alice"); self.mk_user("bob")
        self.assertEqual(self.c.post("/api/users/bob/disable", headers=self.hdr("alice")).status_code, 403)

    def test_reserved_usernames_refused(self):
        """Usernames equal to shared-role actor names would let account flags affect role-credential sessions."""
        with self.assertRaises(ValueError): create_user(self.app.db, "red_team-operator", RED, PW)

    def test_disable_is_audited(self):
        self.mk_user("alice"); self.c.post("/api/users/alice/disable", headers=self.E)
        self.assertIn("USER_DISABLED", self.c.get("/api/audit", headers=self.E).text)


class TestVisibilityAndMigration(Base):
    def test_unassigned_users_do_not_see_assigned_tests(self):
        """Test names/counts are information; assigned tests are hidden from other Red users."""
        self.mk_user("red1"); self.mk_user("red2")
        t = self.c.post("/api/tests", json={"name": "Hidden from red2"}, headers=self.E).json(); tid = t.get("test_id") or t["id"]
        self.c.post(f"/api/tests/{tid}/participants", json={"actor": "red1", "role": "RED_TEAM"}, headers=self.E)
        names = lambda u: [x["name"] for x in self.c.get("/api/tests", headers=self.hdr(u)).json()["tests"]]
        self.assertIn("Hidden from red2", names("red1")); self.assertNotIn("Hidden from red2", names("red2"))
        self.assertIn("Hidden from red2", [x["name"] for x in self.c.get("/api/tests", headers=self.E).json()["tests"]])

    def test_old_users_table_is_migrated(self):
        """Databases created before MFA/disable/session columns must upgrade in place."""
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True); p = os.path.join(d, "o.db")
        c = sqlite3.connect(p); c.execute("CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL)"); c.commit(); c.close()
        db = DatabaseManager(p); ensure_tables(db)
        with db.connection() as conn: cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        db.close(); self.assertTrue({"disabled", "totp_secret", "totp_pending", "totp_last", "valid_after"} <= cols)


class TestFrontendStatic(unittest.TestCase):
    """The frontend cannot be built in the review sandbox; these guard the security properties in source."""
    def test_gateway_sets_httponly_samesite_cookie_and_hides_token(self):
        """The session token must never be handed to page JavaScript."""
        ts = (ROOT / "server.ts").read_text()
        self.assertIn("HttpOnly; SameSite=Strict", ts)
        self.assertRegex(ts, r"res\.status\(200\)\.json\(\{ role: out\.data\.role, authenticated: true \}\)")

    def test_gateway_enforces_csrf_header_for_cookie_sessions(self):
        """Cookie auth needs a CSRF defence for state-changing requests."""
        ts = (ROOT / "server.ts").read_text()
        self.assertIn("x-requested-with", ts); self.assertIn("CSRF_CHECK_FAILED", ts)

    def test_app_has_no_token_storage_or_password_prompt(self):
        """Tokens must not live in sessionStorage and passwords must not be typed into window.prompt (visible)."""
        app = (ROOT / "src/App.tsx").read_text()
        self.assertNotIn("bayora_token_", app); self.assertNotIn("window.prompt", app)

    def test_login_dialog_masks_password_and_supports_otp(self):
        """Password field must be type=password; OTP input must exist for MFA users."""
        d = (ROOT / "src/components/LoginDialog.tsx").read_text()
        self.assertIn('type="password"', d); self.assertIn("one-time-code", d)

    def test_all_requests_carry_csrf_header(self):
        """getRoleHeaders feeds every API call, so it must add the CSRF header."""
        self.assertIn("'X-Requested-With': 'bayora'", (ROOT / "src/App.tsx").read_text())


if __name__ == "__main__":
    unittest.main()
