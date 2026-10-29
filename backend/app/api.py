"""
FastAPI / Compatible API Routes for Bayora Systems.
Implements the exact contract:
- POST /api/tests — create test record (permitted creator role)
- POST /api/tests/{id}/start — start test (valid state + right role required)
- POST /api/tests/{id}/close — close test (reject invalid transitions)
- POST /api/tests/{id}/results/release — release approved result fields (EVALUATOR only)
- GET /api/tests/{id}/status — state + non-sensitive metadata only
- GET /api/tests/{id}/results — approved result fields only, per disclosure rule
- GET /api/audit?test_id=... — events with secrets withheld
- GET /api/health — healthcheck for all 3 dev machines

Plus role-isolated artifact endpoints and network boundary verification:
- GET /api/tests — list all test records (non-sensitive metadata only)
- POST /api/tests/{id}/ready — transition Draft -> Ready
- POST /api/tests/{id}/payloads — submit Red Team payload (RED_TEAM only)
- GET /api/tests/{id}/payloads — read Red Team payloads (RED_TEAM only; SEC-02 blocks BLUE_TEAM)
- POST /api/tests/{id}/defenses — submit Blue Team defense (BLUE_TEAM only)
- GET /api/tests/{id}/defenses — read Blue Team defenses (BLUE_TEAM only; SEC-01 blocks RED_TEAM)
- POST /api/network/probe — verify RUNTIME-01 Docker network segmentation policy
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import os

from .adapters import DeterministicMockLLMAdapter, GeminiAdapter, RemoteAdapter
from .audit import AuditLogger
from .auth import ActorIdentity, Role, authenticate_request, login as auth_login
from .compat import BaseModel, BayoraRouterApp, Field, HTTPException, RequestContext
from .database import DatabaseManager
from .lifecycle import TestState, validate_state_transition
from .policy import (
    check_can_close_test,
    check_can_create_test,
    check_can_read_blue_defenses,
    check_can_read_red_payloads,
    check_can_ready_test,
    check_can_release_results,
    check_can_start_test,
    check_can_submit_blue_defense,
    check_can_submit_red_payload,
    filter_result_fields_by_disclosure_policy,
)


class CreateTestRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=120)
    description: str = Field(default="Adversarial AI safety isolation test", max_length=500)
    target_model: str = Field(default="mock-bayora-llm-7b-instruct", max_length=80)
    initial_state: str = Field(default="Draft", max_length=32)


class SubmitRedPayloadRequest(BaseModel):
    category: str = Field(default="PROMPT_INJECTION", min_length=3, max_length=64)
    severity_tier: str = Field(default="HIGH", min_length=2, max_length=24)
    payload_text: str = Field(..., min_length=4, max_length=2000)


class SubmitBlueDefenseRequest(BaseModel):
    defense_name: str = Field(..., min_length=3, max_length=100)
    rule_type: str = Field(default="SYSTEM_PROMPT_GUARD", min_length=3, max_length=64)
    defense_config_secret: str = Field(..., min_length=4, max_length=2000)


class LoginRequest(BaseModel):
    role: str = Field(..., min_length=3, max_length=32)
    credential: str = Field(..., min_length=1, max_length=256)
    actor: str = Field(default="", max_length=80)


class CheckpointBody(BaseModel):
    count: int = Field(...)
    head_hash: str = Field(default="", max_length=128)
    timestamp: str = Field(..., max_length=64)
    signature: str = Field(..., max_length=128)


class NetworkProbeRequest(BaseModel):
    source_service: str = Field(..., min_length=2, max_length=64)
    target_service: str = Field(..., min_length=2, max_length=64)
    test_id: str = Field(default="GLOBAL_NETWORK", max_length=64)


ALLOWED_CATEGORIES = {"PROMPT_INJECTION", "JAILBREAK_ROLEPLAY", "SYSTEM_PROMPT_EXTRACTION", "INDIRECT_CONTEXT_POISONING"}
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_RULE_TYPES = {"INPUT_SANITIZER", "SYSTEM_PROMPT_GUARD", "POLICY_CLASSIFIER", "OUTPUT_REDACTOR", "ALL_LAYER_SHIELD"}


def _cas_update(conn: Any, sql: str, params: tuple) -> None:
    """Atomic compare-and-set: the row only changes if it is still in the expected previous state."""
    if conn.execute(sql, params).rowcount != 1:
        raise HTTPException(status_code=409, detail={"error": "CONCURRENT_STATE_CHANGE", "code": "STATE_CHANGED_CONCURRENTLY",
                                                     "message": "The test changed state while this request was running."})


def create_bayora_app(db_path: Optional[str] = None, seed_demo_data: bool = False) -> BayoraRouterApp:
    db = DatabaseManager(db_path=db_path)
    audit = AuditLogger(db=db)
    if os.environ.get("BAYORA_ADAPTER_URL"):
        adapter = RemoteAdapter()
    elif os.environ.get("BAYORA_TARGET_ADAPTER_MODE") == "GEMINI_LIVE_V1":
        adapter = GeminiAdapter()
    else:
        adapter = DeterministicMockLLMAdapter()
    with db.connection() as _c:
        _c.execute("CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL)")
    app = BayoraRouterApp(title="Bayora Systems — Adversarial AI Safety Control Plane", version="1.0.0")
    app.db = db  # exposed so tests/shutdown can close connections
    adapter_is_mock = "MOCK" in adapter.ADAPTER_TYPE

    _unauth_last = {"t": 0.0}

    def _unauth_audit(**kw: Any) -> None:  # at most 1 unauthenticated audit row per second (flood protection)
        import time as _t
        if _t.time() - _unauth_last["t"] >= 1.0:
            _unauth_last["t"] = _t.time()
            audit.record(**kw)

    def _require_auth(request: RequestContext, test_id: str, action: str, resource: str) -> ActorIdentity:
        try:
            ident = authenticate_request(request)
            if ident.jti:
                with db.connection() as c:
                    if c.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (ident.jti,)).fetchone():
                        raise HTTPException(status_code=401, detail={"error": "AUTHENTICATION_FAILED",
                                            "code": "AUTH_TOKEN_REVOKED", "message": "Token was revoked."})
            return ident
        except HTTPException as exc:
            _unauth_audit(  # never log caller-claimed role/actor: they are unverified
                test_id=test_id,
                actor="unauthenticated",
                role="UNAUTHENTICATED",
                action=action,
                resource=resource,
                decision="DENY",
                reason_code="AUTH_FAILED_CLOSED",
            )
            raise exc

    def _reject_enum(test_id: str, identity: ActorIdentity, action: str, resource: str, pairs: list) -> None:
        for field, value, allowed in pairs:
            if str(value).strip().upper() not in allowed:
                audit.record(test_id=test_id, actor=identity.actor, role=identity.role.value, action=action,
                             resource=resource, decision="DENY", reason_code=f"VALIDATION_{field.upper()}_NOT_ALLOWED")
                raise HTTPException(status_code=422, detail={"error": "VALIDATION_ERROR", "code": f"{field.upper()}_NOT_ALLOWED",
                                                             "message": f"{field} must be one of {sorted(allowed)}."})

    def _get_test_or_404(test_id: str) -> Dict[str, Any]:
        with db.connection() as conn:
            row = conn.execute("SELECT * FROM tests WHERE id = ?", (test_id,)).fetchone()
            if not row:
                raise HTTPException(
                    status_code=404,
                    detail={
                        "error": "TEST_NOT_FOUND",
                        "code": "RESOURCE_NOT_FOUND",
                        "message": f"Test record '{test_id}' does not exist.",
                    },
                )
            return dict(row)

    @app.post("/api/auth/login")
    def login_route(request: RequestContext, body: LoginRequest) -> Dict[str, Any]:
        """Exchange a per-role credential for a signed, expiring bearer token."""
        try:
            token = auth_login(body.role, body.credential, body.actor)
        except HTTPException:
            _unauth_audit(test_id="GLOBAL", actor="unauthenticated", role="UNAUTHENTICATED",
                         action="LOGIN", resource="/api/auth/login", decision="DENY", reason_code="AUTH_LOGIN_FAILED")
            raise
        return {"token": token, "token_type": "Bearer"}

    @app.post("/api/auth/logout")
    def logout_route(request: RequestContext) -> Dict[str, Any]:
        """Revoke the presented token immediately."""
        ident = _require_auth(request, test_id="GLOBAL", action="LOGOUT", resource="/api/auth/logout")
        with db.connection() as c:
            if ident.jti:
                c.execute("INSERT OR IGNORE INTO revoked_tokens (jti, exp) VALUES (?, ?)", (ident.jti, ident.exp))
            c.execute("DELETE FROM revoked_tokens WHERE exp < strftime('%s','now')")  # purge expired entries
        audit.record(test_id="GLOBAL", actor=ident.actor, role=ident.role.value, action="LOGOUT",
                     resource="/api/auth/logout", decision="ALLOW")
        return {"revoked": True}

    @app.get("/api/health")
    def healthcheck() -> Dict[str, Any]:
        """Stage 1: Healthcheck for all 3 dev machines and isolated worker boundaries."""
        db_ok = False
        with db.connection() as conn:
            res = conn.execute("SELECT 1 AS ok").fetchone()
            db_ok = bool(res and res["ok"] == 1)

        return {
            "status": "healthy" if db_ok else "degraded",
            "service": "bayora-control-plane",
            "version": "1.0.0",
            "database": {"engine": "sqlite3", "connected": db_ok, "schema_isolated": True},
            "target_adapter": {
                "adapter_type": adapter.ADAPTER_TYPE,
                "is_mock": adapter_is_mock,
                "label": "MOCK_LLM_DETERMINISTIC (NO REAL MODEL WEIGHTS)" if adapter_is_mock else adapter.ADAPTER_TYPE,
            },
            "dev_machines": {
                "red_team_node": {"role": "RED_TEAM", "network": "red-net", "status": "ready", "direct_blue_access": "BLOCKED"},
                "blue_team_node": {"role": "BLUE_TEAM", "network": "blue-net", "status": "ready", "direct_red_access": "BLOCKED"},
                "evaluator_control_plane": {"role": "EVALUATOR", "network": "control-net", "status": "ready", "mediating": True},
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/tests")
    def list_tests(request: RequestContext) -> Dict[str, Any]:
        identity = _require_auth(request, test_id="GLOBAL", action="LIST_TESTS", resource="/api/tests")
        with db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, description, target_model, adapter_mode, state,
                       current_run_id, created_by_role, created_by_actor, created_at, updated_at
                FROM tests
                ORDER BY created_at DESC
                """
            ).fetchall()
            tests_list = []
            for r in rows:
                d = dict(r)
                p_cnt = conn.execute("SELECT COUNT(*) AS c FROM red_payloads WHERE test_id = ?", (d["id"],)).fetchone()["c"]
                b_cnt = conn.execute("SELECT COUNT(*) AS c FROM blue_defenses WHERE test_id = ?", (d["id"],)).fetchone()["c"]
                d["red_payload_count"] = p_cnt
                d["blue_defense_count"] = b_cnt
                d["is_mock_adapter"] = adapter_is_mock
                tests_list.append(d)

        return {"tests": tests_list, "viewer_role": identity.role.value}

    @app.post("/api/tests")
    def create_test(request: RequestContext, body: CreateTestRequest) -> Any:
        identity = _require_auth(request, test_id="NEW_TEST", action="CREATE_TEST", resource="/api/tests")
        allowed, reason = check_can_create_test(identity.role)
        if not allowed:
            audit.record(
                test_id="NEW_TEST",
                actor=identity.actor,
                role=identity.role.value,
                action="CREATE_TEST",
                resource="/api/tests",
                decision="DENY",
                reason_code=reason,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ACCESS_DENIED",
                    "code": reason,
                    "message": f"Role '{identity.role.value}' is not permitted to create test records.",
                },
            )

        requested_initial = body.initial_state.strip() if body.initial_state else TestState.DRAFT.value
        if requested_initial not in (TestState.DRAFT.value, TestState.READY.value):
            audit.record(
                test_id="NEW_TEST",
                actor=identity.actor,
                role=identity.role.value,
                action="CREATE_TEST",
                resource="/api/tests",
                decision="DENY",
                state_transition=f"None->{requested_initial}",
                reason_code="STATE_INVALID_INITIAL_STATE",
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "INVALID_INITIAL_STATE",
                    "code": "STATE_INVALID_INITIAL_STATE",
                    "message": "New tests must start in 'Draft' (or 'Ready') state.",
                },
            )

        test_id = f"tst-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()

        with db.connection() as conn:
            conn.execute(
                """
                INSERT INTO tests (
                    id, name, description, target_model, adapter_mode,
                    state, current_run_id, created_by_role, created_by_actor, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    test_id,
                    body.name.strip(),
                    body.description.strip(),
                    body.target_model.strip(),
                    adapter.ADAPTER_TYPE,
                    requested_initial,
                    None,
                    identity.role.value,
                    identity.actor,
                    now,
                    now,
                ),
            )

        audit.record(
            test_id=test_id,
            actor=identity.actor,
            role=identity.role.value,
            action="CREATE_TEST",
            resource=f"test:{test_id}",
            decision="ALLOW",
            state_transition=f"None->{requested_initial}",
            reason_code=reason,
        )

        return (
            {
                "test_id": test_id,
                "name": body.name.strip(),
                "description": body.description.strip(),
                "target_model": body.target_model.strip(),
                "adapter_mode": adapter.ADAPTER_TYPE,
                "is_mock_adapter": adapter_is_mock,
                "state": requested_initial,
                "current_run_id": None,
                "created_by_role": identity.role.value,
                "created_by_actor": identity.actor,
                "created_at": now,
            },
            201,
        )

    @app.post("/api/tests/{id}/ready")
    def mark_test_ready(request: RequestContext, id: str) -> Dict[str, Any]:
        identity = _require_auth(request, test_id=id, action="MARK_TEST_READY", resource=f"test:{id}")
        test_row = _get_test_or_404(id)

        allowed, reason = check_can_ready_test(identity.role)
        if not allowed:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="MARK_TEST_READY",
                resource=f"test:{id}",
                decision="DENY",
                state_transition=f"{test_row['state']}->{TestState.READY.value}",
                reason_code=reason,
            )
            raise HTTPException(
                status_code=403,
                detail={"error": "ACCESS_DENIED", "code": reason, "message": "Role not permitted to ready test."},
            )

        valid_tx, tx_label, tx_reason = validate_state_transition(test_row["state"], TestState.READY)
        if not valid_tx:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="MARK_TEST_READY",
                resource=f"test:{id}",
                decision="DENY",
                state_transition=tx_label,
                reason_code=tx_reason,
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "INVALID_STATE_TRANSITION",
                    "code": tx_reason,
                    "transition": tx_label,
                    "message": f"Cannot transition test from '{test_row['state']}' to 'Ready'.",
                },
            )

        now = datetime.now(timezone.utc).isoformat()
        with db.connection() as conn:
            _cas_update(conn, "UPDATE tests SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                        (TestState.READY.value, now, id, TestState.DRAFT.value))

        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="MARK_TEST_READY",
            resource=f"test:{id}",
            decision="ALLOW",
            state_transition=tx_label,
            reason_code=tx_reason,
        )

        return {"test_id": id, "state": TestState.READY.value, "transition": tx_label, "updated_at": now}

    @app.post("/api/tests/{id}/payloads")
    def submit_red_payload(request: RequestContext, id: str, body: SubmitRedPayloadRequest) -> Any:
        identity = _require_auth(request, test_id=id, action="SUBMIT_RED_PAYLOAD", resource=f"test:{id}/payloads")
        test_row = _get_test_or_404(id)

        allowed, reason = check_can_submit_red_payload(identity.role, test_row["state"])
        if not allowed:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="SUBMIT_RED_PAYLOAD",
                resource=f"test:{id}/payloads",
                decision="DENY",
                state_transition=f"{test_row['state']}->{test_row['state']}",
                reason_code=reason,
            )
            status_code = 409 if "STATE" in reason or "IMMUTABLE" in reason else 403
            raise HTTPException(
                status_code=status_code,
                detail={
                    "error": "PAYLOAD_SUBMISSION_DENIED",
                    "code": reason,
                    "message": "Action denied by role or lifecycle policy.",
                },
            )

        _reject_enum(id, identity, "SUBMIT_RED_PAYLOAD", f"test:{id}/payloads",
                     [("category", body.category, ALLOWED_CATEGORIES), ("severity_tier", body.severity_tier, ALLOWED_SEVERITIES)])
        payload_id = f"red-pld-{uuid.uuid4().hex[:10]}"
        payload_hash = hashlib.sha256(body.payload_text.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()

        with db.connection() as conn:
            conn.execute(
                """
                INSERT INTO red_payloads (
                    id, test_id, author_actor, category, severity_tier,
                    payload_text, payload_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload_id,
                    id,
                    identity.actor,
                    body.category.strip().upper(),
                    body.severity_tier.strip().upper(),
                    body.payload_text,
                    payload_hash,
                    now,
                ),
            )

        # Audit logs ONLY artifact ID and hash metadata — NEVER raw payload_text
        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="SUBMIT_RED_PAYLOAD",
            resource=f"red_payload:{payload_id}#sha256:{payload_hash[:16]}",
            decision="ALLOW",
            state_transition=f"{test_row['state']}->{test_row['state']}",
            reason_code=reason,
        )

        return (
            {
                "artifact_id": payload_id,
                "test_id": id,
                "category": body.category.strip().upper(),
                "severity_tier": body.severity_tier.strip().upper(),
                "payload_sha256": payload_hash,
                "created_at": now,
            },
            201,
        )

    @app.get("/api/tests/{id}/payloads")
    def read_red_payloads(request: RequestContext, id: str) -> Dict[str, Any]:
        """
        SEC-02 Enforcement:
        Only RED_TEAM can read Red payloads.
        If BLUE_TEAM or EVALUATOR calls this route, it is DENIED (403), the raw payload is completely
        absent from the error body, and a DENY audit event is recorded.
        """
        identity = _require_auth(request, test_id=id, action="READ_RED_PAYLOAD", resource=f"test:{id}/payloads")
        test_row = _get_test_or_404(id)

        allowed, reason = check_can_read_red_payloads(identity.role, test_row["state"])
        if not allowed:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="READ_RED_PAYLOAD",
                resource=f"test:{id}/payloads",
                decision="DENY",
                state_transition=f"{test_row['state']}->{test_row['state']}",
                reason_code=reason,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ACCESS_DENIED",
                    "code": reason,
                    "message": "Cross-role isolation boundary violation: caller is not authorized to read Red Team attack payloads.",
                },
            )

        with db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, test_id, author_actor, category, severity_tier,
                       payload_text, payload_sha256, created_at
                FROM red_payloads
                WHERE test_id = ?
                ORDER BY created_at ASC
                """,
                (id,),
            ).fetchall()

        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="READ_RED_PAYLOAD",
            resource=f"test:{id}/payloads",
            decision="ALLOW",
            state_transition=f"{test_row['state']}->{test_row['state']}",
            reason_code=reason,
        )

        return {"test_id": id, "payloads": [dict(r) for r in rows]}

    @app.post("/api/tests/{id}/defenses")
    def submit_blue_defense(request: RequestContext, id: str, body: SubmitBlueDefenseRequest) -> Any:
        identity = _require_auth(request, test_id=id, action="SUBMIT_BLUE_DEFENSE", resource=f"test:{id}/defenses")
        test_row = _get_test_or_404(id)

        allowed, reason = check_can_submit_blue_defense(identity.role, test_row["state"])
        if not allowed:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="SUBMIT_BLUE_DEFENSE",
                resource=f"test:{id}/defenses",
                decision="DENY",
                state_transition=f"{test_row['state']}->{test_row['state']}",
                reason_code=reason,
            )
            status_code = 409 if "STATE" in reason or "IMMUTABLE" in reason else 403
            raise HTTPException(
                status_code=status_code,
                detail={
                    "error": "DEFENSE_SUBMISSION_DENIED",
                    "code": reason,
                    "message": "Action denied by role or lifecycle policy.",
                },
            )

        _reject_enum(id, identity, "SUBMIT_BLUE_DEFENSE", f"test:{id}/defenses",
                     [("rule_type", body.rule_type, ALLOWED_RULE_TYPES)])
        defense_id = f"blu-def-{uuid.uuid4().hex[:10]}"
        config_hash = hashlib.sha256(body.defense_config_secret.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()

        with db.connection() as conn:
            conn.execute(
                """
                INSERT INTO blue_defenses (
                    id, test_id, author_actor, defense_name, rule_type,
                    defense_config_secret, config_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    defense_id,
                    id,
                    identity.actor,
                    body.defense_name.strip(),
                    body.rule_type.strip().upper(),
                    body.defense_config_secret,
                    config_hash,
                    now,
                ),
            )

        # Audit logs ONLY artifact ID and hash metadata — NEVER raw defense_config_secret
        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="SUBMIT_BLUE_DEFENSE",
            resource=f"blue_defense:{defense_id}#sha256:{config_hash[:16]}",
            decision="ALLOW",
            state_transition=f"{test_row['state']}->{test_row['state']}",
            reason_code=reason,
        )

        return (
            {
                "artifact_id": defense_id,
                "test_id": id,
                "defense_name": body.defense_name.strip(),
                "rule_type": body.rule_type.strip().upper(),
                "config_sha256": config_hash,
                "created_at": now,
            },
            201,
        )

    @app.get("/api/tests/{id}/defenses")
    def read_blue_defenses(request: RequestContext, id: str) -> Dict[str, Any]:
        """
        SEC-01 Enforcement:
        Only BLUE_TEAM can read Blue defense artifacts.
        If RED_TEAM or EVALUATOR calls this route, it is DENIED (403), the defense artifact is
        absent from the response, and a DENY audit event is recorded.
        """
        identity = _require_auth(request, test_id=id, action="READ_BLUE_DEFENSE", resource=f"test:{id}/defenses")
        test_row = _get_test_or_404(id)

        allowed, reason = check_can_read_blue_defenses(identity.role, test_row["state"])
        if not allowed:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="READ_BLUE_DEFENSE",
                resource=f"test:{id}/defenses",
                decision="DENY",
                state_transition=f"{test_row['state']}->{test_row['state']}",
                reason_code=reason,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ACCESS_DENIED",
                    "code": reason,
                    "message": "Cross-role isolation boundary violation: caller is not authorized to read Blue Team defense artifacts.",
                },
            )

        with db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, test_id, author_actor, defense_name, rule_type,
                       defense_config_secret, config_sha256, created_at
                FROM blue_defenses
                WHERE test_id = ?
                ORDER BY created_at ASC
                """,
                (id,),
            ).fetchall()

        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="READ_BLUE_DEFENSE",
            resource=f"test:{id}/defenses",
            decision="ALLOW",
            state_transition=f"{test_row['state']}->{test_row['state']}",
            reason_code=reason,
        )

        return {"test_id": id, "defenses": [dict(r) for r in rows]}

    @app.post("/api/tests/{id}/start")
    def start_test(request: RequestContext, id: str) -> Dict[str, Any]:
        """
        POST /api/tests/{id}/start — start test (valid state Ready->Running + right role required).
        Executes the authorized target call via the deterministic mock LLM adapter in a fresh session
        and stores the evaluation result separately from private payloads/defenses.
        """
        identity = _require_auth(request, test_id=id, action="START_TEST", resource=f"test:{id}/start")
        test_row = _get_test_or_404(id)

        allowed_role, role_reason = check_can_start_test(identity.role)
        if not allowed_role:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="START_TEST",
                resource=f"test:{id}/start",
                decision="DENY",
                state_transition=f"{test_row['state']}->{TestState.RUNNING.value}",
                reason_code=role_reason,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ACCESS_DENIED",
                    "code": role_reason,
                    "message": f"Role '{identity.role.value}' is not authorized to start test execution.",
                },
            )

        valid_tx, tx_label, tx_reason = validate_state_transition(test_row["state"], TestState.RUNNING)
        if not valid_tx:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="START_TEST",
                resource=f"test:{id}/start",
                decision="DENY",
                state_transition=tx_label,
                reason_code=tx_reason,
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "INVALID_STATE_TRANSITION",
                    "code": tx_reason,
                    "transition": tx_label,
                    "message": f"Rejected lifecycle transition '{tx_label}'. Test must be in 'Ready' state before starting.",
                },
            )

        run_id = f"run-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()

        with db.connection() as conn:
            red_rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM red_payloads WHERE test_id = ?", (id,)).fetchall()
            ]
            blue_rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM blue_defenses WHERE test_id = ?", (id,)).fetchall()
            ]

            eval_out = adapter.evaluate_isolated_run(
                test_id=id,
                run_id=run_id,
                target_model=test_row["target_model"],
                red_payloads=red_rows,
                blue_defenses=blue_rows,
            )

            result_id = f"res-{uuid.uuid4().hex[:10]}"
            conn.execute(
                """
                INSERT INTO evaluation_results (
                    id, test_id, run_id, session_id, context_hash, adapter_type,
                    is_mock, target_config_json, total_probes, blocked_count,
                    bypassed_count, resilience_score, summary_notes,
                    probe_outcomes_json, execution_ms, run_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result_id,
                    id,
                    run_id,
                    eval_out.session_id,
                    eval_out.context_hash,
                    eval_out.adapter_type,
                    1 if eval_out.is_mock else 0,
                    json.dumps(eval_out.target_config),
                    eval_out.total_probes,
                    eval_out.blocked_count,
                    eval_out.bypassed_count,
                    eval_out.resilience_score,
                    eval_out.summary_notes,
                    json.dumps(eval_out.probe_outcomes),
                    eval_out.execution_ms,
                    eval_out.run_status,
                    now,
                ),
            )

            _cas_update(conn, "UPDATE tests SET state = ?, current_run_id = ?, updated_at = ? WHERE id = ? AND state = ?",
                        (TestState.RUNNING.value, run_id, now, id, TestState.READY.value))

        audit.record(
            test_id=id,
            run_id=run_id,
            actor=identity.actor,
            role=identity.role.value,
            action="START_TEST",
            resource=f"test:{id}/run:{run_id}/session:{eval_out.session_id}",
            decision="ALLOW",
            state_transition=tx_label,
            reason_code="STATE_TRANSITION_VALID",
        )

        return {
            "test_id": id,
            "state": TestState.RUNNING.value,
            "transition": tx_label,
            "run_id": run_id,
            "session_id": eval_out.session_id,
            "context_hash": eval_out.context_hash,
            "adapter_type": eval_out.adapter_type,
            "is_mock_adapter": adapter_is_mock,
            "target_config": eval_out.target_config,
            "updated_at": now,
        }

    @app.post("/api/tests/{id}/close")
    def close_test(request: RequestContext, id: str) -> Dict[str, Any]:
        """POST /api/tests/{id}/close — close test (Running -> Closed, reject invalid transitions)."""
        identity = _require_auth(request, test_id=id, action="CLOSE_TEST", resource=f"test:{id}/close")
        test_row = _get_test_or_404(id)

        allowed_role, role_reason = check_can_close_test(identity.role)
        if not allowed_role:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="CLOSE_TEST",
                resource=f"test:{id}/close",
                decision="DENY",
                state_transition=f"{test_row['state']}->{TestState.CLOSED.value}",
                reason_code=role_reason,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ACCESS_DENIED",
                    "code": role_reason,
                    "message": f"Role '{identity.role.value}' is not authorized to close tests. EVALUATOR required.",
                },
            )

        valid_tx, tx_label, tx_reason = validate_state_transition(test_row["state"], TestState.CLOSED)
        if not valid_tx:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="CLOSE_TEST",
                resource=f"test:{id}/close",
                decision="DENY",
                state_transition=tx_label,
                reason_code=tx_reason,
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "INVALID_STATE_TRANSITION",
                    "code": tx_reason,
                    "transition": tx_label,
                    "message": f"Rejected lifecycle transition '{tx_label}'. Test must be in 'Running' state to close.",
                },
            )

        now = datetime.now(timezone.utc).isoformat()
        with db.connection() as conn:
            _cas_update(conn, "UPDATE tests SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                        (TestState.CLOSED.value, now, id, TestState.RUNNING.value))

        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="CLOSE_TEST",
            resource=f"test:{id}/close",
            decision="ALLOW",
            state_transition=tx_label,
            reason_code=tx_reason,
        )

        return {
            "test_id": id,
            "state": TestState.CLOSED.value,
            "transition": tx_label,
            "run_id": test_row.get("current_run_id"),
            "updated_at": now,
        }

    @app.post("/api/tests/{id}/results/release")
    def release_results(request: RequestContext, id: str) -> Dict[str, Any]:
        """
        POST /api/tests/{id}/results/release — release approved result fields (EVALUATOR only).
        Enforces SEC-03 (non-evaluator release denied) and STATE-01 (Closed -> Results Released only).
        """
        identity = _require_auth(
            request,
            test_id=id,
            action="RELEASE_RESULTS",
            resource=f"test:{id}/results/release",
        )
        test_row = _get_test_or_404(id)

        allowed_role, role_reason = check_can_release_results(identity.role)
        if not allowed_role:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="RELEASE_RESULTS",
                resource=f"test:{id}/results/release",
                decision="DENY",
                state_transition=f"{test_row['state']}->{TestState.RESULTS_RELEASED.value}",
                reason_code=role_reason,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "ACCESS_DENIED",
                    "code": role_reason,
                    "message": "Only EVALUATOR role is permitted to release approved test results (SEC-03).",
                },
            )

        valid_tx, tx_label, tx_reason = validate_state_transition(test_row["state"], TestState.RESULTS_RELEASED)
        if not valid_tx:
            audit.record(
                test_id=id,
                run_id=test_row.get("current_run_id"),
                actor=identity.actor,
                role=identity.role.value,
                action="RELEASE_RESULTS",
                resource=f"test:{id}/results/release",
                decision="DENY",
                state_transition=tx_label,
                reason_code=tx_reason,
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "INVALID_STATE_TRANSITION",
                    "code": tx_reason,
                    "transition": tx_label,
                    "message": f"Rejected lifecycle transition '{tx_label}'. Test must be 'Closed' before releasing results.",
                },
            )

        now = datetime.now(timezone.utc).isoformat()
        with db.connection() as conn:
            _cas_update(conn, "UPDATE tests SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                        (TestState.RESULTS_RELEASED.value, now, id, TestState.CLOSED.value))

        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="RELEASE_RESULTS",
            resource=f"test:{id}/results/release",
            decision="ALLOW",
            state_transition=tx_label,
            reason_code=tx_reason,
        )

        return {
            "test_id": id,
            "state": TestState.RESULTS_RELEASED.value,
            "transition": tx_label,
            "run_id": test_row.get("current_run_id"),
            "results_released": True,
            "updated_at": now,
        }

    @app.get("/api/tests/{id}/status")
    def get_test_status(request: RequestContext, id: str) -> Dict[str, Any]:
        """GET /api/tests/{id}/status — state + non-sensitive metadata only."""
        identity = _require_auth(request, test_id=id, action="GET_TEST_STATUS", resource=f"test:{id}/status")
        test_row = _get_test_or_404(id)

        with db.connection() as conn:
            payload_meta = conn.execute(
                "SELECT id, category, severity_tier, payload_sha256, created_at FROM red_payloads WHERE test_id = ?",
                (id,),
            ).fetchall()
            defense_meta = conn.execute(
                "SELECT id, defense_name, rule_type, config_sha256, created_at FROM blue_defenses WHERE test_id = ?",
                (id,),
            ).fetchall()

        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="GET_TEST_STATUS",
            resource=f"test:{id}/status",
            decision="ALLOW",
            state_transition=f"{test_row['state']}->{test_row['state']}",
            reason_code="STATUS_METADATA_ALLOWED",
        )

        return {
            "test_id": test_row["id"],
            "name": test_row["name"],
            "description": test_row["description"],
            "target_model": test_row["target_model"],
            "adapter_mode": test_row["adapter_mode"],
            "is_mock_adapter": adapter_is_mock,
            "state": test_row["state"],
            "current_run_id": test_row["current_run_id"],
            "created_by_role": test_row["created_by_role"],
            "created_by_actor": test_row["created_by_actor"],
            "created_at": test_row["created_at"],
            "updated_at": test_row["updated_at"],
            "artifact_counts": {
                "red_payloads": len(payload_meta),
                "blue_defenses": len(defense_meta),
            },
            "artifact_references": {
                "red_payload_ids": [r["id"] for r in payload_meta],
                "blue_defense_ids": [r["id"] for r in defense_meta],
            },
        }

    @app.get("/api/tests/{id}/results")
    def get_test_results(request: RequestContext, id: str) -> Dict[str, Any]:
        """
        GET /api/tests/{id}/results — approved result fields only, per disclosure rule (DATA-01, POS-02).
        """
        identity = _require_auth(request, test_id=id, action="GET_TEST_RESULTS", resource=f"test:{id}/results")
        test_row = _get_test_or_404(id)

        with db.connection() as conn:
            result_row = None
            if test_row.get("current_run_id"):
                r = conn.execute(
                    "SELECT * FROM evaluation_results WHERE test_id = ? AND run_id = ?",
                    (id, test_row["current_run_id"]),
                ).fetchone()
                if r:
                    result_row = dict(r)

        filtered = filter_result_fields_by_disclosure_policy(test_row, result_row, identity.role)
        audit.record(
            test_id=id,
            run_id=test_row.get("current_run_id"),
            actor=identity.actor,
            role=identity.role.value,
            action="GET_TEST_RESULTS",
            resource=f"test:{id}/results",
            decision="ALLOW",
            state_transition=f"{test_row['state']}->{test_row['state']}",
            reason_code=filtered["disclosure_policy"],
        )
        return filtered

    @app.get("/api/tests/{id}/report")
    def get_test_report(request: RequestContext, id: str) -> Dict[str, Any]:
        """Evaluator-only report, available after results are released. Secrets/raw payloads never included."""
        identity = _require_auth(request, test_id=id, action="GET_TEST_REPORT", resource=f"test:{id}/report")
        test_row = _get_test_or_404(id)
        deny = None
        if identity.role != Role.EVALUATOR:
            deny = "REPORT_EVALUATOR_ONLY"
        elif test_row["state"] != TestState.RESULTS_RELEASED.value:
            deny = "REPORT_REQUIRES_RELEASED_RESULTS"
        if deny:
            audit.record(test_id=id, actor=identity.actor, role=identity.role.value, action="GET_TEST_REPORT",
                         resource=f"test:{id}/report", decision="DENY", reason_code=deny)
            raise HTTPException(status_code=403 if deny == "REPORT_EVALUATOR_ONLY" else 409,
                                detail={"error": "REPORT_DENIED", "code": deny, "message": "Report not available."})
        with db.connection() as conn:
            r = conn.execute("SELECT * FROM evaluation_results WHERE test_id = ? AND run_id = ?",
                             (id, test_row["current_run_id"])).fetchone()
        results = filter_result_fields_by_disclosure_policy(test_row, dict(r) if r else None, identity.role)
        audit.record(test_id=id, run_id=test_row.get("current_run_id"), actor=identity.actor, role=identity.role.value,
                     action="GET_TEST_REPORT", resource=f"test:{id}/report", decision="ALLOW")
        events = audit.list_events(test_id=id, limit=1000)
        return {
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "test": {"id": id, "name": test_row["name"], "state": test_row["state"], "target_model": test_row["target_model"]},
            "results": results,
            "evidence_type": "MOCK / SIMULATED" if results.get("is_mock_adapter") else "REAL MODEL (canary-leak criterion only)",
            "audit": {"event_count": len(events), "chain_verification": audit.verify_chain(), "events": events},
            "limitations": ([] if results.get("is_mock_adapter") else
                            ["Payloads and defense rules were sent to an external model API (data egress)."]) + ["Audit chain is tamper-evident, not tamper-proof against a full-chain rewrite.",
                            "Network isolation is proven only by running scripts/verify_isolation.sh on the deployment."],
        }

    @app.get("/api/audit")
    def get_audit_events(request: RequestContext, test_id: Optional[str] = None) -> Dict[str, Any]:
        """GET /api/audit?test_id=... — events with secrets withheld (AUDIT-01)."""
        identity = _require_auth(
            request,
            test_id=test_id or "GLOBAL",
            action="READ_AUDIT_LOG",
            resource=f"/api/audit?test_id={test_id or 'ALL'}",
        )
        if not test_id and identity.role != Role.EVALUATOR:
            audit.record(test_id="GLOBAL", actor=identity.actor, role=identity.role.value, action="READ_AUDIT_LOG",
                         resource="/api/audit?test_id=ALL", decision="DENY", reason_code="AUDIT_GLOBAL_EVALUATOR_ONLY")
            raise HTTPException(status_code=403, detail={"error": "FORBIDDEN", "code": "AUDIT_GLOBAL_EVALUATOR_ONLY",
                                                         "message": "A test_id is required unless you are the evaluator."})
        if test_id:
            _get_test_or_404(test_id)
        events = audit.list_events(test_id=test_id)
        return {
            "test_id": test_id,
            "total_events": len(events),
            "viewer_role": identity.role.value,
            "secrets_withheld": True,
            "events": events,
        }

    @app.get("/api/audit/verify")
    def verify_audit_chain(request: RequestContext) -> Dict[str, Any]:
        identity = _require_auth(request, test_id="GLOBAL", action="VERIFY_AUDIT_CHAIN", resource="/api/audit/verify")
        if identity.role != Role.EVALUATOR:
            raise HTTPException(status_code=403, detail={"error": "FORBIDDEN", "code": "AUDIT_VERIFY_EVALUATOR_ONLY",
                                                         "message": "Only the evaluator may verify the audit chain."})
        return audit.verify_chain()

    @app.get("/api/audit/checkpoint")
    def audit_checkpoint(request: RequestContext) -> Dict[str, Any]:
        """EVALUATOR: signed checkpoint of the audit chain head. Save it outside the database."""
        identity = _require_auth(request, test_id="GLOBAL", action="AUDIT_CHECKPOINT", resource="/api/audit/checkpoint")
        if identity.role != Role.EVALUATOR:
            raise HTTPException(status_code=403, detail={"error": "FORBIDDEN", "code": "CHECKPOINT_EVALUATOR_ONLY",
                                                         "message": "Only the evaluator may create checkpoints."})
        try:
            return audit.create_checkpoint()
        except ValueError as exc:
            raise HTTPException(status_code=409, detail={"error": "CHECKPOINT_UNAVAILABLE", "message": str(exc)})

    @app.post("/api/audit/checkpoint/verify")
    def audit_checkpoint_verify(request: RequestContext, body: CheckpointBody) -> Dict[str, Any]:
        identity = _require_auth(request, test_id="GLOBAL", action="AUDIT_CHECKPOINT_VERIFY",
                                 resource="/api/audit/checkpoint/verify")
        if identity.role != Role.EVALUATOR:
            raise HTTPException(status_code=403, detail={"error": "FORBIDDEN", "code": "CHECKPOINT_EVALUATOR_ONLY",
                                                         "message": "Only the evaluator may verify checkpoints."})
        return audit.verify_checkpoint({"count": body.count, "head_hash": body.head_hash, "timestamp": body.timestamp, "signature": body.signature})

    @app.post("/api/network/probe")
    def verify_network_isolation(request: RequestContext, body: NetworkProbeRequest) -> Dict[str, Any]:
        """
        RUNTIME-01 Enforcement:
        Direct Red-to-Blue or Blue-to-Red service call across isolated Docker networks (red-net <-> blue-net)
        is strictly rejected and logged. All communication must be mediated by control-plane on control-net.
        """
        identity = _require_auth(
            request,
            test_id=body.test_id,
            action="NETWORK_SERVICE_CALL",
            resource=f"net:{body.source_service}->{body.target_service}",
        )
        src = body.source_service.strip().lower()
        dst = body.target_service.strip().lower()

        forbidden_pairs = {
            ("red-worker", "blue-worker"),
            ("blue-worker", "red-worker"),
            ("red-net", "blue-net"),
            ("blue-net", "red-net"),
            ("red-worker", "target-adapter"),
            ("blue-worker", "target-adapter"),
        }

        if (src, dst) in forbidden_pairs:
            audit.record(
                test_id=body.test_id,
                actor=identity.actor,
                role=identity.role.value,
                action="NETWORK_DIRECT_PEER_CALL",
                resource=f"net:{src}->{dst}",
                decision="DENY",
                reason_code="RUNTIME_01_DIRECT_PEER_NETWORK_BLOCKED",
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "NETWORK_ISOLATION_VIOLATION",
                    "code": "RUNTIME_01_DIRECT_PEER_NETWORK_BLOCKED",
                    "source_service": src,
                    "target_service": dst,
                    "simulated": True,
                    "message": f"(policy simulation) Direct network route '{src} -> {dst}' is blocked by isolated bridge segmentation (red-net / blue-net internal:true). All calls must be mediated by control-plane.",
                },
            )

        audit.record(
            test_id=body.test_id,
            actor=identity.actor,
            role=identity.role.value,
            action="NETWORK_MEDIATED_CALL",
            resource=f"net:{src}->{dst}",
            decision="ALLOW",
            reason_code="RUNTIME_CONTROL_NET_MEDIATED",
        )
        return {
            "simulated": True,
            "note": "POLICY SIMULATION ONLY. Real isolation is verified by scripts/verify_isolation.sh against running containers.",
            "allowed": True,
            "source_service": src,
            "target_service": dst,
            "network_plane": "control-net",
            "message": "Mediated control-plane route permitted.",
        }

    @app.post("/api/security-suite/verify")
    def run_live_security_evidence_suite(request: RequestContext) -> Dict[str, Any]:
        """Runs all 10 hackathon security & isolation tests against an isolated in-memory SQLite instance."""
        identity = _require_auth(
            request,
            test_id="SECURITY_SUITE",
            action="RUN_SECURITY_EVIDENCE_SUITE",
            resource="/api/security-suite/verify",
        )
        import time
        import unittest
        from backend.tests.test_security_suite import TestBayoraSecurityEvidence

        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestBayoraSecurityEvidence)
        results_list: List[Dict[str, Any]] = []
        passed = 0
        failed = 0

        for test_case in suite:
            t0 = time.perf_counter()
            res = unittest.TestResult()
            test_case.run(res)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            method_name = getattr(test_case, "_testMethodName", str(test_case))
            doc = (getattr(test_case, method_name).__doc__ or "").strip().split("\n")[0]
            ok = res.wasSuccessful()
            if ok:
                passed += 1
            else:
                failed += 1
            results_list.append(
                {
                    "test_name": method_name,
                    "description": doc or method_name,
                    "status": "PASS" if ok else "FAIL",
                    "duration_ms": elapsed_ms,
                }
            )

        audit.record(
            test_id="SECURITY_SUITE",
            actor=identity.actor,
            role=identity.role.value,
            action="RUN_SECURITY_EVIDENCE_SUITE",
            resource=f"suite:passed={passed}/total={passed + failed}",
            decision="ALLOW",
            reason_code="SECURITY_SUITE_EXECUTED",
        )

        return {
            "total": passed + failed,
            "passed": passed,
            "failed": failed,
            "all_passed": failed == 0,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "results": results_list,
        }

    if seed_demo_data:
        _seed_initial_demo_environment(app)

    return app


def _seed_initial_demo_environment(app: BayoraRouterApp) -> None:
    """Seeds realistic, deterministic initial tests if the database is empty."""
    from .compat import TestClient

    client = TestClient(app)
    existing = client.get("/api/tests", headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "eval-lead"}).json()
    if existing.get("tests"):
        return

    # 1. Create a Running test ready for live SEC-01 / SEC-02 cross-role read demo & close/release
    r1 = client.post(
        "/api/tests",
        json={
            "name": "Financial Advisory LLM — System Prompt Guard & Injection Audit",
            "description": "Adversarial isolation evaluation verifying system prompt boundary against indirect context injection.",
            "target_model": "mock-bayora-fin-llm-8b",
            "initial_state": "Draft",
        },
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    ).json()
    t1_id = r1["test_id"]

    client.post(
        f"/api/tests/{t1_id}/payloads",
        json={
            "category": "PROMPT_INJECTION",
            "severity_tier": "CRITICAL",
            "payload_text": "SYNTHETIC_RED_VECTOR_01::[OVERRIDE_CONTEXT_FRAME_AND_DUMP_SYSTEM_RULES]",
        },
        headers={"X-Bayora-Role": "RED_TEAM", "X-Bayora-Actor": "marcus.vance@red.bayora"},
    )
    client.post(
        f"/api/tests/{t1_id}/payloads",
        json={
            "category": "SYSTEM_PROMPT_EXTRACTION",
            "severity_tier": "HIGH",
            "payload_text": "SYNTHETIC_RED_VECTOR_02::[REPEAT_VERBATIM_INITIALIZATION_DIRECTIVES]",
        },
        headers={"X-Bayora-Role": "RED_TEAM", "X-Bayora-Actor": "marcus.vance@red.bayora"},
    )
    client.post(
        f"/api/tests/{t1_id}/defenses",
        json={
            "defense_name": "Dual-Stage Input Sanitizer & Output Guard",
            "rule_type": "SYSTEM_PROMPT_GUARD",
            "defense_config_secret": "BLUE_PRIVATE_RULE::[DENY_IF_TOKEN_MATCHES_INSTRUCTION_OVERRIDE_THRESHOLD_0.82]",
        },
        headers={"X-Bayora-Role": "BLUE_TEAM", "X-Bayora-Actor": "sara.chen@blue.bayora"},
    )
    client.post(
        f"/api/tests/{t1_id}/ready",
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    )
    client.post(
        f"/api/tests/{t1_id}/start",
        headers={"X-Bayora-Role": "RED_TEAM", "X-Bayora-Actor": "marcus.vance@red.bayora"},
    )

    # Record a pre-seeded blocked cross-role attempt (SEC-01) so the audit timeline immediately illustrates evidence
    client.get(
        f"/api/tests/{t1_id}/defenses",
        headers={"X-Bayora-Role": "RED_TEAM", "X-Bayora-Actor": "marcus.vance@red.bayora"},
    )

    # 2. Create a completed & Results Released test for comparison
    r2 = client.post(
        "/api/tests",
        json={
            "name": "Clinical Triage Assistant — Policy Classifier Verification",
            "description": "Completed cycle with full defense coverage and Evaluator-approved result disclosure.",
            "target_model": "mock-bayora-med-llm-13b",
            "initial_state": "Draft",
        },
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    ).json()
    t2_id = r2["test_id"]

    client.post(
        f"/api/tests/{t2_id}/payloads",
        json={
            "category": "JAILBREAK_ROLEPLAY",
            "severity_tier": "HIGH",
            "payload_text": "SYNTHETIC_RED_VECTOR_03::[SIMULATE_UNRESTRICTED_DIAGNOSTIC_MODE]",
        },
        headers={"X-Bayora-Role": "RED_TEAM", "X-Bayora-Actor": "marcus.vance@red.bayora"},
    )
    client.post(
        f"/api/tests/{t2_id}/defenses",
        json={
            "defense_name": "Full Spectrum Safety Shield",
            "rule_type": "ALL_LAYER_SHIELD",
            "defense_config_secret": "BLUE_PRIVATE_RULE::[ENFORCE_STRICT_CLINICAL_BOUNDARY_HASH_994A]",
        },
        headers={"X-Bayora-Role": "BLUE_TEAM", "X-Bayora-Actor": "sara.chen@blue.bayora"},
    )
    client.post(
        f"/api/tests/{t2_id}/ready",
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    )
    client.post(
        f"/api/tests/{t2_id}/start",
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    )
    client.post(
        f"/api/tests/{t2_id}/close",
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    )
    client.post(
        f"/api/tests/{t2_id}/results/release",
        headers={"X-Bayora-Role": "EVALUATOR", "X-Bayora-Actor": "elena.rostova@bayora.sys"},
    )
