# Bayora Systems — Secure Adversarial AI Testing Environment

**Hack in Hills '26 Prototype** | **Theme**: AI Safety Testing, Container & Network Isolation, Access Control, Auditability

Bayora Systems protects the integrity of adversarial AI safety evaluations by enforcing strict separation between **Red Team attack payloads**, **Blue Team defensive configurations**, and **Target LLM session state** until an authorized **Evaluator** closes the test and releases approved results. Every allowed and denied action produces a tamper-evident, secret-free audit record.

---

## Architecture & Repository Layout

```text
bayora/
├── README.md                         # Setup, test commands, architecture, honest status
├── compose.yaml                      # Hardened Docker Compose (red-net, blue-net, control-net)
├── .env.example                      # Placeholder environment variables (no secrets)
├── docs/
│   ├── problem-and-scope.md          # Core problem statement and prototype boundaries
│   ├── threat-model.md               # Protected assets and trust boundaries
│   ├── api-contract.md               # Exact REST API specification and RBAC rules
│   ├── decisions.md                  # Architectural decisions and verification status
│   └── demo-script.md                # Step-by-step live demo walkthrough
├── backend/
│   ├── requirements.txt              # stdlib only (no third-party deps)
│   ├── app/
│   │   ├── api.py                    # API routes + server-side Pydantic/schema validation
│   │   ├── auth.py                   # Fail-closed role authentication (RED_TEAM, BLUE_TEAM, EVALUATOR)
│   │   ├── policy.py                 # RBAC, SEC-01/02/03 isolation, DATA-01 disclosure filter
│   │   ├── lifecycle.py              # Strict state machine (Draft->Ready->Running->Closed->Results Released)
│   │   ├── audit.py                  # Secret-free audit event logger (ALLOW & DENY)
│   │   ├── adapters.py               # Deterministic Mock LLM Adapter with fresh session isolation
│   │   ├── database.py               # Isolated SQLite tables scoped by test_id
│   │   └── main.py                   # Python HTTP / ASGI server entrypoint
│   └── tests/
│       └── test_security_suite.py    # Automated positive & negative security test suite
├── workers/
│   ├── red/                          # Isolated Red Team worker container (red-net)
│   ├── blue/                         # Isolated Blue Team worker container (blue-net)
│   └── target-adapter/               # Isolated Target LLM Adapter container (control-net)
├── infra/docker/                     # Non-root hardened Dockerfiles for backend & frontend
└── src/                              # React + Vite Role-Based Control Plane Dashboard
```

---

## Quickstart & Running Tests

### 1. Run Python Security & Isolation Tests
```bash
python3 -m unittest discover -s backend/tests -v
```

### 2. Run Frontend / Logic Unit Tests
```bash
tsx --test src/lib/bayoraLogic.test.ts
```

### 3. Start Full-Stack Environment (Express + Python Control Plane + React UI on Port 3000)
```bash
npm run dev
```

### 4. Run Hardened Multi-Network Docker Compose (On a Docker Host)
```bash
cp .env.example .env
docker compose up --build
```

---

## Security Evidence Matrix

| Test ID | Security Requirement | Enforcement Mechanism | Status |
| :--- | :--- | :--- | :--- |
| **SEC-01** | Red reads unreleased Blue defense artifact | Denied (`403`), artifact excluded from error body, `DENY` audit logged | **VERIFIED (PASS)** |
| **SEC-02** | Blue reads unreleased Red payload | Denied (`403`), payload excluded from error body, `DENY` audit logged | **VERIFIED (PASS)** |
| **SEC-03** | Non-evaluator releases results | Denied (`403`) for `RED_TEAM` & `BLUE_TEAM`, state unchanged, `DENY` logged | **VERIFIED (PASS)** |
| **STATE-01** | Invalid lifecycle transition (`Draft→Released`, `Closed→Running`, `Running→Ready`) | Rejected (`409`), state uncorrupted, attempted transition logged | **VERIFIED (PASS)** |
| **DATA-01** | Read results before `Results Released` | Returns only non-sensitive metadata; evaluation scores withheld | **VERIFIED (PASS)** |
| **MODEL-01** | Consecutive tests start with fresh context | `DeterministicMockLLMAdapter` generates new `run_id`, `session_id`, and `context_hash` | **VERIFIED (PASS)** |
| **AUDIT-01** | Denied & allowed requests recorded without secrets | Every event records timestamp, role, action, resource hash/ID, decision, transition | **VERIFIED (PASS)** |
| **RUNTIME-01** | Direct Red-to-Blue network call blocked | `red-net` (`internal: true`) & `blue-net` (`internal: true`) + `/api/network/probe` policy | **VERIFIED IN POLICY & COMPOSE CONFIG** *(Live Docker bridge runtime planned/unverified in containerless preview)* |
| **POS-01/02** | Valid Red action & post-release result disclosure | Authorized submission succeeds; Evaluator release unlocks approved metrics | **VERIFIED (PASS)** |


## Setup, auth and verification status (updated)

```bash
cp .env.example .env            # fill every secret with random values: openssl rand -hex 32
docker compose up -d --build    # frontend: http://localhost:3000
./scripts/verify_isolation.sh   # REAL connection attempts from inside the containers
python3 -m unittest discover -s backend/tests -v   # 118 backend tests
```

**Authentication:** callers use `Authorization: Bearer <token>`. Tokens are HMAC-signed, expire (1h default) and are
obtained from `POST /api/auth/login` with the per-role credential from `.env`. signed bearer token (role claim)s are ignored.
`BAYORA_DEV_HEADER_AUTH=1` (demo only) lets the gateway sign a token for the UI role switcher; keep it `0` in real use.

| Capability | Status |
|---|---|
| Lifecycle, RBAC policy, disclosure filter | Unit-tested |
| Signed-token auth, spoof/expiry/tamper rejection | Unit-tested |
| Audit hash chain + `/api/audit/verify` | Unit-tested (tamper-EVIDENT, not tamper-proof vs. full-chain rewrite) |
| Network isolation | Config + `scripts/verify_isolation.sh`; **run it on your Docker host to confirm** |
| `/api/network/probe` | Policy simulation only (response says `simulated: true`) |
| Target adapter service | Wired: control plane calls it over authenticated HTTP in Compose (`BAYORA_ADAPTER_URL`); integration-tested locally |
| Real-model adapter | `GEMINI_LIVE_V1` implemented (set `BAYORA_TARGET_ADAPTER_MODE=GEMINI_LIVE_V1` + `GEMINI_API_KEY`); criterion = canary leak only; **untested against the live API**. Default results are MOCK and labelled so |
| Token revocation | `POST /api/auth/logout` revokes the token immediately (unit-tested) |
| Docker build, frontend build, full UI journey | Unverified here (no Docker/Node/network in the review sandbox) |

**Notes (updated):** audit actor names are assigned by the server per role (`BAYORA_<ROLE>_ACTOR`), not chosen by callers, so
the audit trail attributes actions to a role identity, not an individual person. Role credentials must be >= 16 chars outside
demo mode. A correct credential is never locked out; wrong guesses are throttled after 5 failures per role. Request bodies are
capped at 1 MB and CORS is off unless `BAYORA_CORS_ORIGIN` is set. Add `package-lock.json` by running `npm install` once.

**Run in one command (no Docker):** `./scripts/dev.sh` (Mac/Linux) or `.\scripts\dev.ps1` (Windows PowerShell), then open http://localhost:3000.
Demo data is opt-in (`BAYORA_SEED_DEMO=1`). **CI:** `.github/workflows/ci.yml` runs backend tests, frontend lint/build/tests and the
Docker isolation check on every push, so push this repo to GitHub to get the Docker/frontend verification I could not run.
**Audit checkpoints:** `GET /api/audit/checkpoint` (evaluator) returns a signed head hash; store it outside the database and later
`POST /api/audit/checkpoint/verify` it. This detects even a full-chain rewrite. Set a separate `BAYORA_AUDIT_KEY` to keep the key apart from login secrets.

## Tests and known limitations (current)
`python3 -m unittest discover -s backend/tests -v` runs 118 tests in two files: `test_security_suite.py` (original + auth/audit/report
fixes) and `test_extended.py` (role matrix, lifecycle, validation, secret leakage, auth edge cases, audit tamper/checkpoint,
adapters + adapter service, concurrency, real-HTTP behaviour, DB migration, deployment-config checks). Each test has a docstring
stating the failure it prevents. Deployment-config tests need PyYAML (`pip install pyyaml`) and are skipped without it.

Fixed in this version: atomic compare-and-set state transitions (no double start/release), allow-listed category/severity/rule
type, strict JSON type checks (no 500s), slow-client timeouts, Gemini requires `BAYORA_ALLOW_EXTERNAL_MODEL=1` and records data
egress, production CSP on the gateway, demo data opt-in.

Still limitations (by design / not verifiable here):
- One shared credential per role, no per-person accounts, no per-test ownership: any Red user can write to any test.
- No TLS inside the stack; put a TLS-terminating reverse proxy in front for anything beyond localhost.
- Login throttling and the unauthenticated-audit limiter are in-memory (reset on restart, not shared across processes).
- Tokens live in `sessionStorage` (CSP reduces, does not remove, XSS risk).
- Docker build, frontend build and the live Gemini call are unverified here; CI (`.github/workflows/ci.yml`) runs them.
