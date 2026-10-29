# Problem & Scope — Bayora Systems (Hack in Hills '26)

## One-Sentence Goal
Build a prototype that protects the integrity of the adversarial AI test itself: Red Team payloads, Blue Team defenses, and client LLM state must stay separate until an approved result release, with audit evidence for every allowed and denied action.

## The Core Problem
In typical AI red-teaming exercises, Red Team operators, Blue Team defenders, and the target LLM share a common notebook, API gateway, or logging pipeline. This creates three severe integrity failures:
1. **Cross-Team Artifact Leakage**: If Blue Team can inspect unreleased Red Team attack vectors, they can overfit regex filters to the exact prompt strings. Conversely, if Red Team can read Blue Team's active guard configuration before a test closes, they can trivially craft bypasses.
2. **State Contamination Across Runs**: If consecutive tests share a persistent LLM conversation buffer or memory cache, earlier adversarial payloads can poison subsequent test runs (`MODEL-01`).
3. **Log & Error Body Leakage**: Generic API error responses or audit logs that copy raw request bodies inadvertently expose secret payloads and defense configurations to unauthorized viewers (`AUDIT-01`).

## Scope of This Prototype
- **In Scope**:
  - Three explicit server-enforced roles: `RED_TEAM`, `BLUE_TEAM`, `EVALUATOR`.
  - Strict 5-stage lifecycle state machine: `Draft → Ready → Running → Closed → Results Released`.
  - Isolated SQLite tables for tests, Red payloads, Blue defenses, evaluation results, and audit events.
  - Deterministic Mock LLM Adapter (`MOCK_DETERMINISTIC_V1`) clearly labeled and instantiating a fresh ephemeral `session_id` per run.
  - Complete audit evidence trail capturing both `ALLOW` and `DENY` decisions without storing raw secrets.
  - Hardened multi-network Docker Compose architecture (`red-net`, `blue-net`, `control-net`).
- **Out of Scope / Honest Limitations**:
  - Live multi-host kernel eBPF packet filtering (simulated via control-plane network probe policy in single-container preview environments where the Docker daemon is not mounted).
  - Real frontier LLM weights in default runs (runs use the deterministic mock adapter by default so results are 100% repeatable and clearly labeled).
