> **Update:** identity is now a signed bearer token (`POST /api/auth/login`); signed bearer token (role claim)s are ignored except in demo mode (`BAYORA_DEV_HEADER_AUTH=1`). See README. Older header-based wording below is superseded.

# Threat Model — Bayora Systems

## Assets to Protect
1. **Red Team Attack Payloads (`red_payloads.payload_text`)**: Proprietary or sensitive adversarial prompts. Must never be visible to `BLUE_TEAM` (`SEC-02`) or copied into audit logs (`AUDIT-01`).
2. **Blue Team Defense Configurations (`blue_defenses.defense_config_secret`)**: Guardrail thresholds, canary tokens, and classifier rules. Must never be visible to `RED_TEAM` (`SEC-01`) or copied into audit logs.
3. **Target LLM Session Context**: Must be initialized fresh for every test run (`MODEL-01`) so prior runs cannot poison or influence subsequent evaluations.
4. **Unreleased Evaluation Metrics**: Detailed pass/bypass scores must remain withheld (`DATA-01`) until an authorized `EVALUATOR` transitions a `Closed` test to `Results Released` (`SEC-03`).

## Trust Boundaries
- **Boundary 1 — Role & API Policy Gateway**: Every HTTP request is authenticated via `signed bearer token role` and `X-Bayora-Actor`. Missing or unrecognized identities fail closed (`401`/`403`) before any controller logic executes.
- **Boundary 2 — Network Segmentation (`red-net`, `blue-net`, `control-net`)**:
  - `red-worker` resides on `red-net` (`internal: true`).
  - `blue-worker` resides on `blue-net` (`internal: true`).
  - Neither worker shares a bridge network with the other or with `target-adapter`. Only `control-plane` bridges approved requests (`RUNTIME-01`).
- **Boundary 3 — Storage & Error Sanitization**:
  - Denied responses return structured policy error codes (`SEC_01_RED_READ_BLUE_DEFENSE_DENIED`, `SEC_02_BLUE_READ_RED_PAYLOAD_DENIED`) and never echo the target record.
  - Audit records reference artifacts strictly by `artifact_id` and SHA-256 hash prefix.
