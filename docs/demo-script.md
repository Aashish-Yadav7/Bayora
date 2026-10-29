> **Update:** identity is now a signed bearer token (`POST /api/auth/login`); signed bearer token (role claim)s are ignored except in demo mode (`BAYORA_DEV_HEADER_AUTH=1`). See README. Older header-based wording below is superseded.

# Hackathon Demo Script — Bayora Systems (3-Minute Live Walkthrough)

Follow this sequence in the Bayora Dashboard (or via `curl`) to demonstrate all security boundaries end-to-end:

1. **Step 1 — Create Test (`Draft` State)**:
   - Select **Evaluator (`EVALUATOR`)** or **Red Team (`RED_TEAM`)** in the active role bar.
   - Create a new test or select an existing `Draft` test. Observe that `GET /api/tests/{id}/results` returns `WITHHELD_PENDING_EVALUATOR_RELEASE` (`DATA-01`).
2. **Step 2 — Stage Isolated Artifacts (`POS-01`)**:
   - Switch to **Red Team (`RED_TEAM`)** and submit an attack payload (`POST /api/tests/{id}/payloads`).
   - Switch to **Blue Team (`BLUE_TEAM`)** and submit a defense rule (`POST /api/tests/{id}/defenses`).
   - Click **Stage to Ready (`Draft → Ready`)** and **Start Execution (`Ready → Running`)**. Observe the fresh `run_id`, `session_id`, and `MOCK_DETERMINISTIC_V1` badge (`MODEL-01`).
3. **Step 3 — Attempt Cross-Role Reads (`SEC-01` & `SEC-02` Blocked)**:
   - While acting as **Red Team**, click **Attempt Read Blue Defense (`SEC-01`)**.
   - Observe the `HTTP 403 Forbidden` banner: the backend blocks the call, the secret Blue defense rule is completely absent from the response body, and a `DENY` audit record appears immediately in the **Audit Evidence Timeline**.
   - Switch to **Blue Team** and click **Attempt Read Red Payload (`SEC-02`)**. Observe the same fail-closed `403` boundary and `DENY` audit log.
4. **Step 4 — Attempt Invalid Transition / Unauthorized Release (`STATE-01` & `SEC-03`)**:
   - While still in `Running` state (or as Red/Blue Team), click **Attempt Early Result Release**. Observe the backend rejection (`403` for non-evaluator `SEC-03`, or `409 Conflict` for `Running → Results Released` `STATE-01`).
5. **Step 5 — Close & Release Approved Results (`POS-02`)**:
   - Switch to **Evaluator (`EVALUATOR`)**.
   - Click **Close Test (`Running → Closed`)**, then click **Release Approved Results (`Closed → Results Released`)**.
   - Inspect the **Approved Evaluation Results** panel: resilience score, blocked/bypassed counts, and hashed probe verdicts are now visible to all roles, while raw payloads and raw defense secrets remain permanently withheld.
