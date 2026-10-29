import { BayoraRole, LifecycleState } from '../lib/bayoraLogic';

export interface TestSummary {
  id: string;
  name: string;
  description: string;
  target_model: string;
  adapter_mode: string;
  is_mock_adapter: boolean;
  state: LifecycleState;
  current_run_id: string | null;
  created_by_role: BayoraRole;
  created_by_actor: string;
  created_at: string;
  updated_at: string;
  red_payload_count: number;
  blue_defense_count: number;
}

export interface TestStatusResponse {
  test_id: string;
  name: string;
  description: string;
  target_model: string;
  adapter_mode: string;
  is_mock_adapter: boolean;
  state: LifecycleState;
  current_run_id: string | null;
  created_by_role: BayoraRole;
  created_by_actor: string;
  created_at: string;
  updated_at: string;
  artifact_counts: {
    red_payloads: number;
    blue_defenses: number;
  };
  artifact_references: {
    red_payload_ids: string[];
    blue_defense_ids: string[];
  };
}

export interface ProbeOutcome {
  probe_index: number;
  payload_artifact_id: string;
  payload_sha256_prefix: string;
  category: string;
  severity_tier: string;
  evaluated_against_defense_hashes: string[];
  verdict: 'BLOCKED_BY_DEFENSE' | 'BYPASSED_TARGET_GUARD';
  mock_response_code: string;
}

export interface ApprovedMetrics {
  total_probes: number;
  blocked_count: number;
  bypassed_count: number;
  resilience_score: number;
  execution_ms: number;
  run_status: string;
  summary_notes: string;
  probe_outcomes: ProbeOutcome[];
}

export interface TestResultsResponse {
  test_id: string;
  test_name: string;
  state: LifecycleState;
  results_released: boolean;
  run_id: string | null;
  session_id?: string;
  context_hash?: string;
  adapter_type?: string;
  is_mock_adapter: boolean;
  adapter_label?: string;
  target_config?: Record<string, unknown>;
  disclosure_policy: string;
  disclosure_notice?: string;
  approved_metrics: ApprovedMetrics | null;
}

export interface RedPayloadArtifact {
  id: string;
  test_id: string;
  author_actor: string;
  category: string;
  severity_tier: string;
  payload_text: string;
  payload_sha256: string;
  created_at: string;
}

export interface BlueDefenseArtifact {
  id: string;
  test_id: string;
  author_actor: string;
  defense_name: string;
  rule_type: string;
  defense_config_secret: string;
  config_sha256: string;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  test_id: string;
  run_id: string | null;
  actor: string;
  role: string;
  action: string;
  resource: string;
  decision: 'ALLOW' | 'DENY';
  state_transition: string | null;
  reason_code: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: {
    engine: string;
    connected: boolean;
    schema_isolated: boolean;
  };
  target_adapter: {
    adapter_type: string;
    is_mock: boolean;
    label: string;
  };
  dev_machines: {
    red_team_node: { role: string; network: string; status: string; direct_blue_access: string };
    blue_team_node: { role: string; network: string; status: string; direct_red_access: string };
    evaluator_control_plane: { role: string; network: string; status: string; mediating: boolean };
  };
  timestamp: string;
}

export interface SecuritySuiteResponse {
  total: number;
  passed: number;
  failed: number;
  all_passed: boolean;
  executed_at: string;
  results: Array<{
    test_name: string;
    description: string;
    status: 'PASS' | 'FAIL';
    duration_ms: number;
  }>;
}
