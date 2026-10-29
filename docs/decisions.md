# Architectural Decisions & Honest Status — Bayora Systems

## Key Decisions
1. **Server-Side Policy Enforcement Before Controller Execution**:
   Frontend role switching is purely for UX ergonomics during the hackathon demonstration. Every API call passes through `authenticate_request()` and `policy.py` checks on the backend before touching SQLite tables.
2. **Artifact Reference Hashing in Audit Ledger (`AUDIT-01`)**:
   Audit logs never accept or store `payload_text` or `defense_config_secret`. When an artifact is created, the audit event records `red_payload:<id>#sha256:<prefix>`, providing cryptographic non-repudiation without leaking the secret content.
3. **Deterministic Mock Adapter First (`MODEL-01`)**:
   To prevent non-deterministic flakiness and clearly distinguish test harness mechanics from live LLM weights, `DeterministicMockLLMAdapter` (`MOCK_DETERMINISTIC_V1`) generates a fresh `session_id` and `context_hash` on every `/start` invocation and labels every response `is_mock: true`.
4. **Hardened Docker Compose Topology**:
   `red-worker` is attached only to `red-net` (`internal: true`), and `blue-worker` is attached only to `blue-net` (`internal: true`). Neither container has root privileges (`USER 10001:10001` / `10002:10002`), capabilities are dropped (`cap_drop: [ALL]`), root filesystems are `read_only: true`, and CPU/memory limits are enforced.

## Verification Status in Container Preview vs Full Docker Host
- **Verified Automated via `unittest` & Live HTTP (`10/10 PASS`)**:
  - `SEC-01`, `SEC-02`, `SEC-03`, `STATE-01`, `DATA-01`, `MODEL-01`, `AUDIT-01`, `RUNTIME-01` (control-plane policy + Compose topology verification), `POS-01`, `POS-02`.
- **Planned / Unverified in Hermetic Cloud Run Preview Sandbox**:
  - Live `docker compose up` kernel bridge packet drop between `red-worker` and `blue-worker` containers is configured in `compose.yaml` and verified structurally via unit tests, but cannot be executed inside the AI Studio preview container because mounting `/var/run/docker.sock` or running nested privileged Docker daemons is disallowed by our own hardening rules and the sandbox environment.
