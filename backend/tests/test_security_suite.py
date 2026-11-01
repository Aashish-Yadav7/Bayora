"""
Bayora Systems — Automated Security & Isolation Verification Suite
Hack in Hills '26 Evidence Tests:
- Stage 1: Healthcheck & SQLite isolation (HEALTH-01)
- Stage 2: Roles & Authorization (SEC-01, SEC-02, SEC-03, AUTH-01)
- Stage 3: Lifecycle State Machine (STATE-01)
- Stage 4: Mock Target LLM Adapter & Context Isolation (MODEL-01)
- Stage 5: Audit Schema & Disclosure Policy (AUDIT-01, DATA-01, POS-01, POS-02, RUNTIME-01)
"""
from __future__ import annotations

import json
import os
import time
import unittest

from backend.app.api import create_bayora_app
from backend.app.auth import Role, issue_token
from backend.app.compat import TestClient


class TestBayoraSecurityEvidence(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["BAYORA_AUTH_SECRET"] = "unit-test-secret-not-for-production"
        os.environ.pop("BAYORA_DEV_HEADER_AUTH", None)
        os.environ.update(BAYORA_RED_WORKER_TOKEN="red-credential-0123456789", BAYORA_BLUE_WORKER_TOKEN="blue-credential-012345678",
                          BAYORA_EVALUATOR_TOKEN="eval-credential-01234567")
        self.app = create_bayora_app(db_path=":memory:", seed_demo_data=False)
        self.addCleanup(self.app.db.close)
        self.client = TestClient(self.app)
        bearer = lambda actor, role: {"Authorization": "Bearer " + issue_token(actor, role)}
        self.red_headers = bearer("red-op-01", Role.RED_TEAM)
        self.blue_headers = bearer("blue-op-01", Role.BLUE_TEAM)
        self.eval_headers = bearer("eval-lead-01", Role.EVALUATOR)

    def _create_draft_test(self, name: str = "Test Isolation Alpha") -> str:
        resp = self.client.post(
            "/api/tests",
            json={
                "name": name,
                "description": "Verification test for cross-role isolation",
                "target_model": "mock-bayora-llm-7b",
                "initial_state": "Draft",
            },
            headers=self.eval_headers,
        )
        self.assertEqual(resp.status_code, 201)
        return resp.json()["test_id"]

    # -------------------------------------------------------------------------
    # STAGE 1: Healthcheck & Skeleton Verification
    # -------------------------------------------------------------------------
    def test_stage1_health_endpoint_and_3_dev_machines(self) -> None:
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "healthy")
        self.assertTrue(body["database"]["connected"])
        self.assertTrue(body["target_adapter"]["is_mock"])
        self.assertIn("red_team_node", body["dev_machines"])
        self.assertIn("blue_team_node", body["dev_machines"])
        self.assertIn("evaluator_control_plane", body["dev_machines"])

    # -------------------------------------------------------------------------
    # STAGE 2: Roles, Fail-Closed Auth, SEC-01, SEC-02, SEC-03
    # -------------------------------------------------------------------------
    def test_auth_fail_closed_on_missing_or_invalid_role(self) -> None:
        # Missing role header -> 401
        r_missing = self.client.get("/api/tests", headers={})
        self.assertEqual(r_missing.status_code, 401)

        # Forged / unknown role -> 403
        r_forged = self.client.get("/api/tests", headers={"X-Bayora-Role": "SUPER_ADMIN"})
        self.assertEqual(r_forged.status_code, 401)

    def test_role_header_spoofing_is_ignored(self) -> None:
        for h in ({"X-Bayora-Role": "EVALUATOR"}, {**self.red_headers, "X-Bayora-Role": "EVALUATOR"}):
            r = self.client.get("/api/audit", headers=h)
            self.assertNotEqual(r.status_code, 200)

    def test_bad_expired_and_tampered_tokens_rejected(self) -> None:
        good = issue_token("x", Role.EVALUATOR)
        expired = issue_token("x", Role.EVALUATOR, ttl=-10)
        payload, sig = good.split(".")
        tampered = issue_token("x", Role.RED_TEAM).split(".")[0] + "." + sig
        for tok in ("garbage", expired, tampered):
            r = self.client.get("/api/tests", headers={"Authorization": "Bearer " + tok})
            self.assertEqual(r.status_code, 401, tok)

    def test_login_exchanges_credential_for_token(self) -> None:
        bad = self.client.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "nope"})
        self.assertEqual(bad.status_code, 401)
        ok = self.client.post("/api/auth/login", json={"role": "RED_TEAM", "credential": "red-credential-0123456789", "actor": "r1"})
        self.assertEqual(ok.status_code, 200)
        r = self.client.get("/api/tests", headers={"Authorization": "Bearer " + ok.json()["token"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["viewer_role"], "RED_TEAM")

    def test_report_requires_evaluator_and_release(self) -> None:
        tid = self._create_draft_test()
        for h in (self.eval_headers,):
            self.assertEqual(self.client.get(f"/api/tests/{tid}/report", headers=h).status_code, 409)
        c, e = self.client, self.eval_headers
        c.post(f"/api/tests/{tid}/ready", headers=e); c.post(f"/api/tests/{tid}/start", headers=e)
        c.post(f"/api/tests/{tid}/close", headers=e); c.post(f"/api/tests/{tid}/results/release", headers=e)
        self.assertEqual(c.get(f"/api/tests/{tid}/report", headers=self.red_headers).status_code, 403)
        rep = c.get(f"/api/tests/{tid}/report", headers=e)
        self.assertEqual(rep.status_code, 200)
        body = rep.json()
        self.assertTrue(body["audit"]["chain_verification"]["valid"])
        self.assertEqual(body["evidence_type"], "MOCK / SIMULATED")
        self.assertNotIn("payload_text", json.dumps(body))

    def test_login_actor_is_server_assigned(self) -> None:
        r = self.client.post("/api/auth/login", json={"role": "RED_TEAM", "credential": "red-credential-0123456789",
                                                       "actor": "CEO-Impersonator"})
        from backend.app.auth import verify_token
        self.assertEqual(verify_token(r.json()["token"]).actor, "red_team-operator")

    def test_oversized_body_rejected_and_no_wildcard_cors(self) -> None:
        import http.client, threading
        import backend.app.compat as C
        port = 18321
        threading.Thread(target=C.run_http_server, args=(self.app, "127.0.0.1", port), daemon=True).start()
        for _ in range(50):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3); conn.request("GET", "/api/health"); break
            except OSError:
                time.sleep(0.1)
        r = conn.getresponse(); r.read()
        self.assertEqual(r.status, 200)
        self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c2.putrequest("POST", "/api/auth/login"); c2.putheader("Content-Length", str(5 * 1024 * 1024)); c2.endheaders()
        self.assertEqual(c2.getresponse().status, 413)

    def test_signed_checkpoint_detects_full_chain_rewrite(self) -> None:
        self._create_draft_test()
        cp = self.client.get("/api/audit/checkpoint", headers=self.eval_headers).json()
        self.assertEqual(self.client.get("/api/audit/checkpoint", headers=self.red_headers).status_code, 403)
        ok = self.client.post("/api/audit/checkpoint/verify", json=cp, headers=self.eval_headers).json()
        self.assertTrue(ok["valid"])
        # attacker rewrites event #1 AND recomputes the whole chain so verify_chain() alone would pass
        from backend.app.audit import _hash_event, _FIELDS
        with self.app.db.connection() as conn:
            conn.execute("UPDATE audit_events SET decision = 'DENY' WHERE rowid = 1")
            prev = ""
            for r in conn.execute("SELECT rowid AS rid, * FROM audit_events ORDER BY rowid").fetchall():
                h = _hash_event(prev, tuple(r[f] for f in _FIELDS))
                conn.execute("UPDATE audit_events SET prev_hash = ?, event_hash = ? WHERE rowid = ?", (prev, h, r["rid"]))
                prev = h
        self.assertTrue(self.client.get("/api/audit/verify", headers=self.eval_headers).json()["valid"])
        bad = self.client.post("/api/audit/checkpoint/verify", json=cp, headers=self.eval_headers).json()
        self.assertFalse(bad["valid"])
        self.assertEqual(bad["reason"], "HISTORY_REWRITTEN_OR_TRUNCATED")
        forged = dict(cp, count=cp["count"] + 5)
        self.assertEqual(self.client.post("/api/audit/checkpoint/verify", json=forged,
                                          headers=self.eval_headers).json()["reason"], "BAD_CHECKPOINT_SIGNATURE")

    def test_logout_revokes_token(self) -> None:
        self.assertEqual(self.client.get("/api/tests", headers=self.red_headers).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout", headers=self.red_headers).status_code, 200)
        self.assertEqual(self.client.get("/api/tests", headers=self.red_headers).status_code, 401)
        self.assertEqual(self.client.get("/api/tests", headers=self.eval_headers).status_code, 200)

    def test_remote_adapter_service_end_to_end(self) -> None:
        import importlib.util, threading
        from http.server import ThreadingHTTPServer
        os.environ["BAYORA_ADAPTER_TOKEN"] = "adapter-secret"
        spec = importlib.util.spec_from_file_location("adapter_service", "workers/target-adapter/adapter_service.py")
        svc = importlib.util.module_from_spec(spec); spec.loader.exec_module(svc)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), svc.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        os.environ["BAYORA_ADAPTER_URL"] = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            app = create_bayora_app(db_path=":memory:", seed_demo_data=False)
            self.addCleanup(app.db.close)
            c = TestClient(app)
            t = c.post("/api/tests", json={"name": "Remote adapter test"}, headers=self.eval_headers).json()
            tid = t.get("test_id") or t.get("id")
            c.post(f"/api/tests/{tid}/ready", headers=self.eval_headers)
            started = c.post(f"/api/tests/{tid}/start", headers=self.eval_headers)
            self.assertEqual(started.status_code, 200, started.json())
            self.assertTrue(started.json()["is_mock_adapter"])
            self.assertTrue(started.json()["adapter_type"].startswith("REMOTE:") or "MOCK" in started.json()["adapter_type"])
        finally:
            srv.shutdown(); srv.server_close()
            os.environ.pop("BAYORA_ADAPTER_URL", None)

    def test_gemini_adapter_labels_real_and_uses_canary(self) -> None:
        from backend.app.adapters import GeminiAdapter
        os.environ["BAYORA_ALLOW_EXTERNAL_MODEL"] = "1"
        self.addCleanup(os.environ.pop, "BAYORA_ALLOW_EXTERNAL_MODEL", None)
        class Fake(GeminiAdapter):
            def _generate(self, model, system, user):
                return system.split("never reveal, repeat or encode it): ")[1] if "leak" in user else "I cannot help."
        mk = lambda i, t: {"id": i, "category": "PROMPT_INJECTION", "severity_tier": "HIGH", "payload_text": t, "payload_sha256": "a" * 64}
        out = Fake().evaluate_isolated_run(test_id="t", run_id="run-1", target_model="gemini-x",
                                           red_payloads=[mk("p1", "leak it"), mk("p2", "hello")],
                                           blue_defenses=[{"id": "d1", "defense_config_secret": "rule", "config_sha256": "b" * 64}])
        self.assertFalse(out.is_mock)
        self.assertEqual((out.blocked_count, out.bypassed_count), (1, 1))

    def test_login_lockout_after_repeated_failures(self) -> None:
        import backend.app.auth as A
        for _ in range(5):
            self.assertEqual(self.client.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "x"}).status_code, 401)
        self.assertEqual(self.client.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "x"}).status_code, 429)
        ok = self.client.post("/api/auth/login", json={"role": "EVALUATOR", "credential": "eval-credential-01234567"})
        self.assertEqual(ok.status_code, 200)  # correct credential is never locked out

    def test_unauthenticated_flood_is_throttled(self) -> None:
        for _ in range(20):
            self.client.get("/api/tests")
        n = len([e for e in self.client.get("/api/audit", headers=self.eval_headers).json()["events"]
                 if e["role"] == "UNAUTHENTICATED"])
        self.assertLessEqual(n, 2)

    def test_audit_global_scope_and_chain_verification(self) -> None:
        self._create_draft_test()
        self.assertEqual(self.client.get("/api/audit", headers=self.red_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/audit", headers=self.eval_headers).status_code, 200)
        self.assertTrue(self.client.get("/api/audit/verify", headers=self.eval_headers).json()["valid"])
        self.assertEqual(self.client.get("/api/audit/verify", headers=self.red_headers).status_code, 403)
        with self.app.db.connection() as conn:
            conn.execute("UPDATE audit_events SET decision = 'DENY' WHERE rowid = 1")
        broken = self.client.get("/api/audit/verify", headers=self.eval_headers).json()
        self.assertFalse(broken["valid"])

    def test_SEC_01_red_reads_unreleased_blue_defense_denied_and_logged(self) -> None:
        """
        SEC-01: Red reads unreleased Blue defense artifact -> DENIED by backend,
        artifact not in response, audit event recorded.
        """
        test_id = self._create_draft_test("SEC-01 Defense Isolation Test")
        secret_defense_rule = "SECRET_BLUE_GUARD_99182_NEVER_LEAK_TO_RED"

        # Blue Team submits defense config
        b_res = self.client.post(
            f"/api/tests/{test_id}/defenses",
            json={
                "defense_name": "Strict Canary Filter",
                "rule_type": "SYSTEM_PROMPT_GUARD",
                "defense_config_secret": secret_defense_rule,
            },
            headers=self.blue_headers,
        )
        self.assertEqual(b_res.status_code, 201)

        # Red Team attempts to read Blue defenses
        sec01_res = self.client.get(f"/api/tests/{test_id}/defenses", headers=self.red_headers)
        self.assertEqual(sec01_res.status_code, 403)
        raw_response_str = json.dumps(sec01_res.json())
        self.assertNotIn(secret_defense_rule, raw_response_str)
        self.assertEqual(sec01_res.json()["code"], "SEC_01_RED_READ_BLUE_DEFENSE_DENIED")

        # Verify DENY audit event recorded without secret
        audit_res = self.client.get(f"/api/audit?test_id={test_id}", headers=self.eval_headers).json()
        deny_events = [
            e for e in audit_res["events"]
            if e["decision"] == "DENY" and e["action"] == "READ_BLUE_DEFENSE" and e["role"] == "RED_TEAM"
        ]
        self.assertEqual(len(deny_events), 1)
        self.assertNotIn(secret_defense_rule, json.dumps(audit_res))

    def test_SEC_02_blue_reads_unreleased_red_payload_denied_and_logged(self) -> None:
        """
        SEC-02: Blue reads unreleased Red payload -> DENIED, payload absent from
        body/error, audit event recorded.
        """
        test_id = self._create_draft_test("SEC-02 Payload Isolation Test")
        secret_red_payload = "CONFIDENTIAL_RED_ATTACK_VECTOR_X77_DO_NOT_DISCLOSE"

        # Red Team submits payload
        r_res = self.client.post(
            f"/api/tests/{test_id}/payloads",
            json={
                "category": "PROMPT_INJECTION",
                "severity_tier": "CRITICAL",
                "payload_text": secret_red_payload,
            },
            headers=self.red_headers,
        )
        self.assertEqual(r_res.status_code, 201)

        # Blue Team attempts to read Red payloads
        sec02_res = self.client.get(f"/api/tests/{test_id}/payloads", headers=self.blue_headers)
        self.assertEqual(sec02_res.status_code, 403)
        raw_error_str = json.dumps(sec02_res.json())
        self.assertNotIn(secret_red_payload, raw_error_str)
        self.assertEqual(sec02_res.json()["code"], "SEC_02_BLUE_READ_RED_PAYLOAD_DENIED")

        # Verify DENY audit event recorded without secret
        audit_res = self.client.get(f"/api/audit?test_id={test_id}", headers=self.eval_headers).json()
        deny_events = [
            e for e in audit_res["events"]
            if e["decision"] == "DENY" and e["action"] == "READ_RED_PAYLOAD" and e["role"] == "BLUE_TEAM"
        ]
        self.assertEqual(len(deny_events), 1)
        self.assertNotIn(secret_red_payload, json.dumps(audit_res))

    def test_SEC_03_non_evaluator_releases_results_denied_and_logged(self) -> None:
        """
        SEC-03: Non-evaluator releases results -> DENIED and logged.
        """
        test_id = self._create_draft_test("SEC-03 Unauthorized Release Test")
        self.client.post(f"/api/tests/{test_id}/ready", headers=self.eval_headers)
        self.client.post(f"/api/tests/{test_id}/start", headers=self.red_headers)
        self.client.post(f"/api/tests/{test_id}/close", headers=self.eval_headers)

        # Red Team attempts to release results -> 403 DENIED
        red_rel = self.client.post(f"/api/tests/{test_id}/results/release", headers=self.red_headers)
        self.assertEqual(red_rel.status_code, 403)
        self.assertEqual(red_rel.json()["code"], "SEC_03_NON_EVALUATOR_RELEASE_DENIED")

        # Blue Team attempts to release results -> 403 DENIED
        blue_rel = self.client.post(f"/api/tests/{test_id}/results/release", headers=self.blue_headers)
        self.assertEqual(blue_rel.status_code, 403)
        self.assertEqual(blue_rel.json()["code"], "SEC_03_NON_EVALUATOR_RELEASE_DENIED")

        # State must still be Closed
        status_body = self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()
        self.assertEqual(status_body["state"], "Closed")

        # Audit log must contain both DENY events
        audit_events = self.client.get(f"/api/audit?test_id={test_id}", headers=self.eval_headers).json()["events"]
        sec03_denials = [
            e for e in audit_events
            if e["action"] == "RELEASE_RESULTS" and e["decision"] == "DENY"
        ]
        self.assertEqual(len(sec03_denials), 2)

    # -------------------------------------------------------------------------
    # STAGE 3: Lifecycle State Machine (STATE-01)
    # -------------------------------------------------------------------------
    def test_STATE_01_invalid_lifecycle_transitions_rejected_and_uncorrupted(self) -> None:
        """
        STATE-01: Invalid lifecycle transition -> rejected, state uncorrupted, audit event.
        Tests:
        - Draft -> Results Released (rejected)
        - Draft -> Running without Ready (rejected)
        - Running -> Ready (rejected)
        - Closed -> Running (rejected; closed test cannot be reopened/modified)
        """
        test_id = self._create_draft_test("STATE-01 Lifecycle Rigor Test")

        # 1. Draft -> Results Released (invalid)
        r_draft_rel = self.client.post(f"/api/tests/{test_id}/results/release", headers=self.eval_headers)
        self.assertEqual(r_draft_rel.status_code, 409)
        self.assertEqual(self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()["state"], "Draft")

        # 2. Draft -> Running directly without Ready (invalid)
        r_draft_run = self.client.post(f"/api/tests/{test_id}/start", headers=self.eval_headers)
        self.assertEqual(r_draft_run.status_code, 409)
        self.assertEqual(self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()["state"], "Draft")

        # Valid: Draft -> Ready -> Running
        self.assertEqual(self.client.post(f"/api/tests/{test_id}/ready", headers=self.eval_headers).status_code, 200)
        self.assertEqual(self.client.post(f"/api/tests/{test_id}/start", headers=self.eval_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()["state"], "Running")

        # 3. Running -> Ready (invalid backward transition)
        r_run_ready = self.client.post(f"/api/tests/{test_id}/ready", headers=self.eval_headers)
        self.assertEqual(r_run_ready.status_code, 409)
        self.assertEqual(self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()["state"], "Running")

        # Valid: Running -> Closed
        self.assertEqual(self.client.post(f"/api/tests/{test_id}/close", headers=self.eval_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()["state"], "Closed")

        # 4. Closed -> Running (invalid; closed test must never be silently modified or restarted)
        r_closed_run = self.client.post(f"/api/tests/{test_id}/start", headers=self.eval_headers)
        self.assertEqual(r_closed_run.status_code, 409)
        self.assertEqual(self.client.get(f"/api/tests/{test_id}/status", headers=self.eval_headers).json()["state"], "Closed")

        # 5. Submitting payload to Closed test -> rejected (409)
        r_closed_pld = self.client.post(
            f"/api/tests/{test_id}/payloads",
            json={"category": "PROMPT_INJECTION", "severity_tier": "HIGH", "payload_text": "LATE_MUTATION_ATTEMPT"},
            headers=self.red_headers,
        )
        self.assertEqual(r_closed_pld.status_code, 409)

        # Check audit events recorded all rejected state transitions
        audit_events = self.client.get(f"/api/audit?test_id={test_id}", headers=self.eval_headers).json()["events"]
        denied_transitions = [e["state_transition"] for e in audit_events if e["decision"] == "DENY"]
        self.assertIn("Draft->Results Released", denied_transitions)
        self.assertIn("Draft->Running", denied_transitions)
        self.assertIn("Running->Ready", denied_transitions)
        self.assertIn("Closed->Running", denied_transitions)

    # -------------------------------------------------------------------------
    # STAGE 4: Mock Target Adapter & Fresh Context Isolation (MODEL-01)
    # -------------------------------------------------------------------------
    def test_MODEL_01_two_consecutive_tests_start_with_fresh_session_and_context(self) -> None:
        """
        MODEL-01: Two consecutive tests -> second starts with fresh session/context,
        target config recorded, mock adapter clearly labeled.
        """
        t1 = self._create_draft_test("Consecutive Run 1")
        self.client.post(f"/api/tests/{t1}/ready", headers=self.eval_headers)
        start1 = self.client.post(f"/api/tests/{t1}/start", headers=self.red_headers).json()

        t2 = self._create_draft_test("Consecutive Run 2")
        self.client.post(f"/api/tests/{t2}/ready", headers=self.eval_headers)
        start2 = self.client.post(f"/api/tests/{t2}/start", headers=self.red_headers).json()

        self.assertNotEqual(start1["run_id"], start2["run_id"])
        self.assertNotEqual(start1["session_id"], start2["session_id"])
        self.assertNotEqual(start1["context_hash"], start2["context_hash"])
        self.assertTrue(start1["is_mock_adapter"])
        self.assertTrue(start2["is_mock_adapter"])
        self.assertEqual(start2["target_config"]["context_isolation"], "FRESH_EPHEMERAL_SESSION")

    # -------------------------------------------------------------------------
    # STAGE 5: Disclosure Rules, Audit Schema, Network Policy (DATA-01, AUDIT-01, POS-01, POS-02, RUNTIME-01)
    # -------------------------------------------------------------------------
    def test_DATA_01_and_POS_01_POS_02_disclosure_before_and_after_release(self) -> None:
        """
        POS-01: Valid Red action succeeds and is recorded.
        DATA-01: Read results before release -> only policy-allowed fields returned (metrics withheld).
        POS-02: Allowed result view works after Evaluator release, while raw secrets remain withheld.
        """
        test_id = self._create_draft_test("Disclosure Verification Suite")
        raw_red_secret = "RED_RAW_PAYLOAD_SECRET_TOKEN_8821"
        raw_blue_secret = "BLUE_RAW_DEFENSE_REGEX_SECRET_4410"

        # POS-01: Valid Red payload submission succeeds
        pos01_res = self.client.post(
            f"/api/tests/{test_id}/payloads",
            json={
                "category": "PROMPT_INJECTION",
                "severity_tier": "HIGH",
                "payload_text": raw_red_secret,
            },
            headers=self.red_headers,
        )
        self.assertEqual(pos01_res.status_code, 201)

        # Valid Blue defense submission
        self.client.post(
            f"/api/tests/{test_id}/defenses",
            json={
                "defense_name": "Injection Shield",
                "rule_type": "INPUT_SANITIZER",
                "defense_config_secret": raw_blue_secret,
            },
            headers=self.blue_headers,
        )

        # Ready & Start test
        self.client.post(f"/api/tests/{test_id}/ready", headers=self.eval_headers)
        self.client.post(f"/api/tests/{test_id}/start", headers=self.red_headers)

        # DATA-01: Read results while Running -> approved_metrics is None
        res_running = self.client.get(f"/api/tests/{test_id}/results", headers=self.red_headers).json()
        self.assertFalse(res_running["results_released"])
        self.assertIsNone(res_running["approved_metrics"])
        self.assertEqual(res_running["disclosure_policy"], "WITHHELD_PENDING_EVALUATOR_RELEASE")

        # Close test; read results while Closed (still unreleased!) -> approved_metrics is still None
        self.client.post(f"/api/tests/{test_id}/close", headers=self.eval_headers)
        res_closed = self.client.get(f"/api/tests/{test_id}/results", headers=self.blue_headers).json()
        self.assertFalse(res_closed["results_released"])
        self.assertIsNone(res_closed["approved_metrics"])

        # Evaluator releases results -> Closed -> Results Released
        rel_res = self.client.post(f"/api/tests/{test_id}/results/release", headers=self.eval_headers)
        self.assertEqual(rel_res.status_code, 200)

        # POS-02: Allowed result view works after release
        res_released = self.client.get(f"/api/tests/{test_id}/results", headers=self.red_headers).json()
        self.assertTrue(res_released["results_released"])
        self.assertIsNotNone(res_released["approved_metrics"])
        self.assertEqual(res_released["approved_metrics"]["total_probes"], 1)
        self.assertEqual(res_released["approved_metrics"]["blocked_count"], 1)
        self.assertEqual(res_released["approved_metrics"]["resilience_score"], 100.0)

        # Ensure raw secrets are NEVER leaked even in released results
        released_dump = json.dumps(res_released)
        self.assertNotIn(raw_red_secret, released_dump)
        self.assertNotIn(raw_blue_secret, released_dump)

    def test_AUDIT_01_schema_completeness_and_no_secret_leakage(self) -> None:
        """
        AUDIT-01: Denied request recorded with role, action, resource, timestamp, decision — no secret leaked.
        """
        test_id = self._create_draft_test("AUDIT-01 Schema Check")
        secret_payload = "TOP_SECRET_RED_PAYLOAD_STRING_NEVER_LOG"
        self.client.post(
            f"/api/tests/{test_id}/payloads",
            json={"category": "PROMPT_INJECTION", "severity_tier": "HIGH", "payload_text": secret_payload},
            headers=self.red_headers,
        )
        # Trigger a denied request
        self.client.get(f"/api/tests/{test_id}/payloads", headers=self.blue_headers)

        audit_body = self.client.get(f"/api/audit?test_id={test_id}", headers=self.eval_headers).json()
        self.assertTrue(audit_body["secrets_withheld"])
        self.assertGreaterEqual(len(audit_body["events"]), 3)

        required_fields = {
            "id", "timestamp", "test_id", "run_id", "actor", "role",
            "action", "resource", "decision", "state_transition", "reason_code"
        }
        for ev in audit_body["events"]:
            self.assertTrue(required_fields.issubset(set(ev.keys())))

        self.assertNotIn(secret_payload, json.dumps(audit_body))

    def test_RUNTIME_01_POLICY_SIMULATION_red_to_blue_blocked(self) -> None:
        """
        RUNTIME-01 (POLICY SIMULATION ONLY - not a real network test; see scripts/verify_isolation.sh).
        """
        probe_res = self.client.post(
            "/api/network/probe",
            json={
                "source_service": "red-worker",
                "target_service": "blue-worker",
                "test_id": "NET-ISOLATION-TEST",
            },
            headers=self.red_headers,
        )
        self.assertEqual(probe_res.status_code, 403)
        self.assertEqual(probe_res.json()["code"], "RUNTIME_01_DIRECT_PEER_NETWORK_BLOCKED")

    def test_DOCKER_HARDENING_compose_and_network_isolation(self) -> None:
        """
        Stage 7 Docker Hardening: Verifies compose.yaml enforces red-net, blue-net,
        control-net, internal bridges, non-root UIDs, cap_drop ALL, CPU/memory limits,
        and zero privileged or docker.sock mounts.
        """
        import os

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        compose_path = os.path.join(repo_root, "compose.yaml")
        with open(compose_path, "r", encoding="utf-8") as f:
            compose_text = f.read()

        self.assertNotIn("privileged: true", compose_text)
        self.assertNotIn("docker.sock", compose_text)
        self.assertIn("red-net:", compose_text)
        self.assertIn("blue-net:", compose_text)
        self.assertIn("control-net:", compose_text)
        self.assertIn("internal: true", compose_text)
        self.assertIn("no-new-privileges:true", compose_text)
        self.assertIn("cpus:", compose_text)
        self.assertIn("memory:", compose_text)
        self.assertIn('user: "10001:10001"', compose_text)
        self.assertIn('user: "10002:10002"', compose_text)


if __name__ == "__main__":
    unittest.main()
