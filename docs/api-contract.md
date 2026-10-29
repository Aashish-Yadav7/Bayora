> **Update:** identity is now a signed bearer token (`POST /api/auth/login`); signed bearer token (role claim)s are ignored except in demo mode (`BAYORA_DEV_HEADER_AUTH=1`). See README. Older header-based wording below is superseded.

# API Contract — Bayora Systems

All protected endpoints require the signed bearer token (role claim) (`RED_TEAM`, `BLUE_TEAM`, or `EVALUATOR`) and optional `X-Bayora-Actor` identifier. Missing or invalid signed bearer tokens fail closed (`401` / `403`) and record a `DENY` audit event.

## Core Lifecycle & Disclosure Routes
| Method | Route | Permitted Roles | Required State | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/tests` | `EVALUATOR`, `RED_TEAM` | `Draft` (initial) | Create a new adversarial test record. |
| `POST` | `/api/tests/{id}/ready` | `EVALUATOR`, `RED_TEAM`, `BLUE_TEAM` | `Draft → Ready` | Lock initial setup and transition test to `Ready`. |
| `POST` | `/api/tests/{id}/start` | `EVALUATOR`, `RED_TEAM` | `Ready → Running` | Execute isolated run against Mock Target Adapter with fresh `session_id`. |
| `POST` | `/api/tests/{id}/close` | `EVALUATOR` | `Running → Closed` | Close test run; test becomes immutable. |
| `POST` | `/api/tests/{id}/results/release` | `EVALUATOR` only (`SEC-03`) | `Closed → Results Released` | Approve and release evaluation summary metrics. |
| `GET` | `/api/tests/{id}/status` | All authenticated roles | Any | Returns current lifecycle state and non-sensitive artifact counts/IDs. |
| `GET` | `/api/tests/{id}/results` | All authenticated roles | Any (`DATA-01` enforced) | Returns withheld notice prior to release; returns approved metrics after `Results Released`. |
| `GET` | `/api/audit?test_id=...` | All authenticated roles (omit `test_id`: EVALUATOR only) | Any | Returns the tamper-evident audit ledger with raw secrets withheld (`AUDIT-01`). |
| `GET` | `/api/health` | Public / All | Any | Healthcheck for control plane, SQLite, mock adapter, and 3 dev nodes. |

## Role-Isolated Artifact & Boundary Routes
| Method | Route | Permitted Roles | Security Control |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/tests/{id}/payloads` | `RED_TEAM` only | Stores private payload in `red_payloads`; logs SHA-256 reference only (`POS-01`). |
| `GET` | `/api/tests/{id}/payloads` | `RED_TEAM` only | Rejects `BLUE_TEAM` & `EVALUATOR` with `403` and zero payload data (`SEC-02`). |
| `POST` | `/api/tests/{id}/defenses` | `BLUE_TEAM` only | Stores private defense rule in `blue_defenses`; logs SHA-256 reference only. |
| `GET` | `/api/tests/{id}/defenses` | `BLUE_TEAM` only | Rejects `RED_TEAM` & `EVALUATOR` with `403` and zero defense data (`SEC-01`). |
| `POST` | `/api/network/probe` | All authenticated roles | Enforces `RUNTIME-01` network policy (`red-worker -> blue-worker` denied). |
