import React, { useState } from 'react';
import {
  BayoraRole,
  computeRoleCapabilities,
} from '../lib/bayoraLogic';
import {
  BlueDefenseArtifact,
  RedPayloadArtifact,
  TestResultsResponse,
  TestStatusResponse,
} from '../types/bayora';
import { Lock, ShieldCheck, Terminal, EyeOff, FileCheck2 } from 'lucide-react';

interface RoleWorkspacePanelProps {
  activeRole: BayoraRole;
  testStatus: TestStatusResponse;
  testResults: TestResultsResponse | null;
  redPayloads: RedPayloadArtifact[];
  blueDefenses: BlueDefenseArtifact[];
  onSubmitRedPayload: (category: string, severity: string, payloadText: string) => Promise<void>;
  onSubmitBlueDefense: (name: string, ruleType: string, secretConfig: string) => Promise<void>;
}

export const RoleWorkspacePanel: React.FC<RoleWorkspacePanelProps> = ({
  activeRole,
  testStatus,
  testResults,
  redPayloads,
  blueDefenses,
  onSubmitRedPayload,
  onSubmitBlueDefense,
}) => {
  const capabilities = computeRoleCapabilities(activeRole, testStatus.state);

  // Red Team Form State
  const [payloadCategory, setPayloadCategory] = useState('PROMPT_INJECTION');
  const [payloadSeverity, setPayloadSeverity] = useState('CRITICAL');
  const [payloadText, setPayloadText] = useState('');
  const [payloadError, setPayloadError] = useState<string | null>(null);
  const [submittingRed, setSubmittingRed] = useState(false);

  // Blue Team Form State
  const [defenseName, setDefenseName] = useState('');
  const [ruleType, setRuleType] = useState('SYSTEM_PROMPT_GUARD');
  const [defenseSecret, setDefenseSecret] = useState('');
  const [defenseError, setDefenseError] = useState<string | null>(null);
  const [submittingBlue, setSubmittingBlue] = useState(false);

  const handleRedSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (payloadText.trim().length < 4) {
      setPayloadError('Attack vector payload must be at least 4 characters.');
      return;
    }
    setPayloadError(null);
    setSubmittingRed(true);
    try {
      await onSubmitRedPayload(payloadCategory, payloadSeverity, payloadText.trim());
      setPayloadText('');
    } finally {
      setSubmittingRed(false);
    }
  };

  const handleBlueSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (defenseName.trim().length < 3) {
      setDefenseError('Defense profile name must be at least 3 characters.');
      return;
    }
    if (defenseSecret.trim().length < 4) {
      setDefenseError('Defense rule configuration must be at least 4 characters.');
      return;
    }
    setDefenseError(null);
    setSubmittingBlue(true);
    try {
      await onSubmitBlueDefense(defenseName.trim(), ruleType, defenseSecret.trim());
      setDefenseName('');
      setDefenseSecret('');
    } finally {
      setSubmittingBlue(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
      {/* Left Column (7 cols): Role-Specific Artifact Isolation Workspace */}
      <section
        aria-label={`${activeRole} Isolated Workspace`}
        className="lg:col-span-7 border border-slate-800 bg-slate-900/60 p-5 rounded-lg flex flex-col justify-between space-y-5"
      >
        {activeRole === 'RED_TEAM' && (
          <div className="space-y-5">
            <div className="border-b border-slate-800 pb-3">
              <div className="text-xs text-rose-400 font-mono">
                <span>RED_TEAM WORKSPACE</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>ISOLATED NETWORK: red-net</span>
              </div>
              <h3 className="text-base font-semibold text-white mt-1 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-rose-400" />
                <span>Private Adversarial Attack Payloads (Isolated from Blue Team)</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Payloads submitted here are stored in <code className="text-slate-300">red_payloads</code> scoped to{' '}
                <code className="text-slate-300">{testStatus.test_id}</code>. Audit logs record only the artifact ID and SHA-256 digest.
              </p>
            </div>

            {/* Submit Red Payload Form */}
            <form onSubmit={handleRedSubmit} className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="red-category" className="block text-xs font-medium text-slate-300 mb-1">
                    Attack Vector Category
                  </label>
                  <select
                    id="red-category"
                    value={payloadCategory}
                    onChange={(e) => setPayloadCategory(e.target.value)}
                    disabled={!capabilities.canSubmitRedPayload}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                  >
                    <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
                    <option value="SYSTEM_PROMPT_EXTRACTION">SYSTEM_PROMPT_EXTRACTION</option>
                    <option value="JAILBREAK_ROLEPLAY">JAILBREAK_ROLEPLAY</option>
                    <option value="INDIRECT_CONTEXT_POISONING">INDIRECT_CONTEXT_POISONING</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="red-severity" className="block text-xs font-medium text-slate-300 mb-1">
                    Severity Tier
                  </label>
                  <select
                    id="red-severity"
                    value={payloadSeverity}
                    onChange={(e) => setPayloadSeverity(e.target.value)}
                    disabled={!capabilities.canSubmitRedPayload}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                  </select>
                </div>
              </div>

              <div>
                <label htmlFor="red-payload-text" className="block text-xs font-medium text-slate-300 mb-1">
                  Synthetic Adversarial Payload Vector (Private to RED_TEAM)
                </label>
                <textarea
                  id="red-payload-text"
                  rows={2}
                  value={payloadText}
                  onChange={(e) => setPayloadText(e.target.value)}
                  disabled={!capabilities.canSubmitRedPayload}
                  placeholder={
                    capabilities.canSubmitRedPayload
                      ? 'Enter synthetic test vector (e.g. SYNTHETIC_PROBE::[IGNORE_PRIOR_CONSTRAINTS_TEST_04])...'
                      : `Test is in '${testStatus.state}' state — payload mutations are locked.`
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                />
                {payloadError && <p className="text-xs text-rose-400 mt-1">{payloadError}</p>}
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  {capabilities.canSubmitRedPayload
                    ? 'Permitted in Draft or Ready state (POS-01)'
                    : `Locked in ${testStatus.state} state (Immutability enforced)`}
                </span>
                <button
                  type="submit"
                  disabled={!capabilities.canSubmitRedPayload || submittingRed}
                  className={`px-4 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    capabilities.canSubmitRedPayload
                      ? 'bg-rose-600 hover:bg-rose-500 text-white cursor-pointer'
                      : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  }`}
                >
                  {submittingRed ? 'Storing Isolated Payload...' : 'Submit Red Payload'}
                </button>
              </div>
            </form>

            {/* Red Payloads Table */}
            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-300">
                Registered Red Payloads ({redPayloads.length})
              </div>
              {redPayloads.length === 0 ? (
                <div className="text-xs text-slate-500 py-4 text-center border border-dashed border-slate-800 rounded">
                  No Red Team payloads registered for this test yet.
                </div>
              ) : (
                <div className="overflow-x-auto border border-slate-800 rounded">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400">
                        <th className="py-2 px-3 font-medium">Artifact ID</th>
                        <th className="py-2 px-3 font-medium">Category · Tier</th>
                        <th className="py-2 px-3 font-medium">Private Vector (RED_TEAM Only)</th>
                        <th className="py-2 px-3 font-medium text-right">SHA-256 Digest</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {redPayloads.map((p) => (
                        <tr key={p.id} className="hover:bg-slate-800/30">
                          <td className="py-2.5 px-3 font-mono text-rose-300 whitespace-nowrap">{p.id}</td>
                          <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                            {p.category} · {p.severity_tier}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-200 max-w-xs truncate" title={p.payload_text}>
                            {p.payload_text}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-400 text-right whitespace-nowrap">
                            {p.payload_sha256.slice(0, 14)}…
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeRole === 'BLUE_TEAM' && (
          <div className="space-y-5">
            <div className="border-b border-slate-800 pb-3">
              <div className="text-xs text-sky-400 font-mono">
                <span>BLUE_TEAM WORKSPACE</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>ISOLATED NETWORK: blue-net</span>
              </div>
              <h3 className="text-base font-semibold text-white mt-1 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-sky-400" />
                <span>Private Defensive Guard Configurations (Isolated from Red Team)</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Defense policies are stored in <code className="text-slate-300">blue_defenses</code> and cannot be read by Red Team operators (<code className="text-slate-300">SEC-01</code>).
              </p>
            </div>

            {/* Submit Blue Defense Form */}
            <form onSubmit={handleBlueSubmit} className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="blue-name" className="block text-xs font-medium text-slate-300 mb-1">
                    Defense Profile Name
                  </label>
                  <input
                    id="blue-name"
                    type="text"
                    value={defenseName}
                    onChange={(e) => setDefenseName(e.target.value)}
                    disabled={!capabilities.canSubmitBlueDefense}
                    placeholder="e.g. Canary Token & Context Boundary Filter"
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                  />
                </div>

                <div>
                  <label htmlFor="blue-rule-type" className="block text-xs font-medium text-slate-300 mb-1">
                    Enforcement Rule Type
                  </label>
                  <select
                    id="blue-rule-type"
                    value={ruleType}
                    onChange={(e) => setRuleType(e.target.value)}
                    disabled={!capabilities.canSubmitBlueDefense}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                  >
                    <option value="SYSTEM_PROMPT_GUARD">SYSTEM_PROMPT_GUARD</option>
                    <option value="INPUT_SANITIZER">INPUT_SANITIZER</option>
                    <option value="POLICY_CLASSIFIER">POLICY_CLASSIFIER</option>
                    <option value="OUTPUT_REDACTOR">OUTPUT_REDACTOR</option>
                    <option value="ALL_LAYER_SHIELD">ALL_LAYER_SHIELD</option>
                  </select>
                </div>
              </div>

              <div>
                <label htmlFor="blue-secret-rule" className="block text-xs font-medium text-slate-300 mb-1">
                  Secret Defense Rule Expression (Private to BLUE_TEAM)
                </label>
                <textarea
                  id="blue-secret-rule"
                  rows={2}
                  value={defenseSecret}
                  onChange={(e) => setDefenseSecret(e.target.value)}
                  disabled={!capabilities.canSubmitBlueDefense}
                  placeholder={
                    capabilities.canSubmitBlueDefense
                      ? 'Enter private guardrail config (e.g. BLUE_RULE::[REJECT_OVERRIDE_SCORE_GT_0.75])...'
                      : `Test is in '${testStatus.state}' state — defense configs are locked.`
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                />
                {defenseError && <p className="text-xs text-rose-400 mt-1">{defenseError}</p>}
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  {capabilities.canSubmitBlueDefense
                    ? 'Permitted in Draft or Ready state'
                    : `Locked in ${testStatus.state} state`}
                </span>
                <button
                  type="submit"
                  disabled={!capabilities.canSubmitBlueDefense || submittingBlue}
                  className={`px-4 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    capabilities.canSubmitBlueDefense
                      ? 'bg-sky-600 hover:bg-sky-500 text-white cursor-pointer'
                      : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  }`}
                >
                  {submittingBlue ? 'Storing Defense...' : 'Save Blue Defense Rule'}
                </button>
              </div>
            </form>

            {/* Blue Defenses Table */}
            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-300">
                Active Blue Defense Artifacts ({blueDefenses.length})
              </div>
              {blueDefenses.length === 0 ? (
                <div className="text-xs text-slate-500 py-4 text-center border border-dashed border-slate-800 rounded">
                  No Blue Team defenses configured for this test yet.
                </div>
              ) : (
                <div className="overflow-x-auto border border-slate-800 rounded">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400">
                        <th className="py-2 px-3 font-medium">Artifact ID</th>
                        <th className="py-2 px-3 font-medium">Defense · Rule Type</th>
                        <th className="py-2 px-3 font-medium">Private Config (BLUE_TEAM Only)</th>
                        <th className="py-2 px-3 font-medium text-right">SHA-256 Digest</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {blueDefenses.map((d) => (
                        <tr key={d.id} className="hover:bg-slate-800/30">
                          <td className="py-2.5 px-3 font-mono text-sky-300 whitespace-nowrap">{d.id}</td>
                          <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                            {d.defense_name} · {d.rule_type}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-200 max-w-xs truncate" title={d.defense_config_secret}>
                            {d.defense_config_secret}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-400 text-right whitespace-nowrap">
                            {d.config_sha256.slice(0, 14)}…
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeRole === 'EVALUATOR' && (
          <div className="space-y-5">
            <div className="border-b border-slate-800 pb-3">
              <div className="text-xs text-emerald-400 font-mono">
                <span>EVALUATOR CONTROL PLANE</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>MEDIATING NETWORK: control-net</span>
              </div>
              <h3 className="text-base font-semibold text-white mt-1 flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-emerald-400" />
                <span>Zero-Trust Orchestration &amp; Non-Sensitive Artifact References</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                As <code className="text-slate-300">EVALUATOR</code>, you coordinate lifecycle transitions (<code className="text-slate-300">Draft → Ready → Running → Closed → Results Released</code>) and verify artifact registration counts without inspecting raw team secrets.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="border border-slate-800 bg-slate-950/60 p-4 rounded">
                <div className="text-xs text-slate-400">Red Team Payload References</div>
                <div className="text-2xl font-bold font-mono text-white mt-1 tabular-nums">
                  {testStatus.artifact_counts.red_payloads}
                </div>
                <div className="text-xs text-slate-400 mt-2 font-mono">
                  {testStatus.artifact_references.red_payload_ids.length > 0
                    ? `IDs: ${testStatus.artifact_references.red_payload_ids.join(', ')}`
                    : 'No payload artifacts staged'}
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950/60 p-4 rounded">
                <div className="text-xs text-slate-400">Blue Team Defense References</div>
                <div className="text-2xl font-bold font-mono text-white mt-1 tabular-nums">
                  {testStatus.artifact_counts.blue_defenses}
                </div>
                <div className="text-xs text-slate-400 mt-2 font-mono">
                  {testStatus.artifact_references.blue_defense_ids.length > 0
                    ? `IDs: ${testStatus.artifact_references.blue_defense_ids.join(', ')}`
                    : 'No defense artifacts staged'}
                </div>
              </div>
            </div>

            <div className="border border-slate-800 bg-slate-950/40 p-4 rounded space-y-2">
              <div className="text-xs font-semibold text-slate-200">
                Evaluator Governance Protocol
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                1. Confirm both Red and Blue teams have registered their artifacts in <strong className="text-slate-200">Draft</strong> or <strong className="text-slate-200">Ready</strong> state.
                <br />
                2. Execute the isolated target run (<strong className="text-slate-200">Ready → Running</strong>) via the deterministic mock LLM adapter.
                <br />
                3. Lock the test (<strong className="text-slate-200">Running → Closed</strong>) so no further payloads or defenses can be injected.
                <br />
                4. Approve disclosure (<strong className="text-slate-200">Closed → Results Released</strong>) to unlock evaluation metrics for all teams.
              </p>
            </div>
          </div>
        )}
      </section>

      {/* Right Column (5 cols): Result Disclosure & Target Adapter Isolation Panel */}
      <section
        aria-label="Evaluation Results and Disclosure Policy"
        className="lg:col-span-5 border border-slate-800 bg-slate-900/60 p-5 rounded-lg flex flex-col justify-between space-y-4"
      >
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <div className="text-xs text-slate-400 font-mono">
              <span>TARGET ADAPTER: MOCK_DETERMINISTIC_V1</span>
              <span className="mx-2" aria-hidden="true">·</span>
              <span>NOT A REAL MODEL</span>
            </div>
            <h3 className="text-base font-semibold text-white mt-1">
              Evaluation Result Disclosure (<code className="text-sm font-mono text-sky-300">GET /api/tests/{testStatus.test_id}/results</code>)
            </h3>
          </div>

          {!testResults || !testResults.results_released || !testResults.approved_metrics ? (
            <div className="border border-amber-800/50 bg-amber-950/20 p-4 rounded space-y-3">
              <div className="flex items-center gap-2 text-amber-300 text-xs font-semibold">
                <EyeOff className="w-4 h-4 shrink-0" />
                <span>DATA-01 Policy Enforced: Results Withheld Prior to Release</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {testResults?.disclosure_notice ||
                  "Evaluation metrics are withheld until EVALUATOR closes the test and approves release ('Closed → Results Released')."}
              </p>
              <div className="pt-2 border-t border-amber-900/40 text-xs font-mono text-slate-400 space-y-1">
                <div>Current Lifecycle State: {testStatus.state}</div>
                <div>Active Run ID: {testStatus.current_run_id || 'Not started'}</div>
                <div>Disclosure Rule: {testResults?.disclosure_policy || 'WITHHELD_PENDING_EVALUATOR_RELEASE'}</div>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="border border-slate-800 bg-slate-950/60 p-3 rounded">
                  <div className="text-xs text-slate-400">Resilience</div>
                  <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5 tabular-nums">
                    {testResults.approved_metrics.resilience_score}%
                  </div>
                </div>
                <div className="border border-slate-800 bg-slate-950/60 p-3 rounded">
                  <div className="text-xs text-slate-400">Blocked Probes</div>
                  <div className="text-xl font-bold font-mono text-white mt-0.5 tabular-nums">
                    {testResults.approved_metrics.blocked_count} / {testResults.approved_metrics.total_probes}
                  </div>
                </div>
                <div className="border border-slate-800 bg-slate-950/60 p-3 rounded">
                  <div className="text-xs text-slate-400">Bypassed</div>
                  <div className="text-xl font-bold font-mono text-rose-400 mt-0.5 tabular-nums">
                    {testResults.approved_metrics.bypassed_count}
                  </div>
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950/60 p-3 rounded text-xs font-mono space-y-1 text-slate-300">
                <div>Run ID: {testResults.run_id}</div>
                <div>Fresh Session ID (MODEL-01): {testResults.session_id}</div>
                <div>Context Hash: {testResults.context_hash}</div>
                <div>Adapter: {testResults.adapter_label}</div>
              </div>

              <div className="space-y-1.5">
                <div className="text-xs font-medium text-slate-300">
                  Sanitized Probe Verdicts (Secret Strings Withheld)
                </div>
                <div className="border border-slate-800 rounded divide-y divide-slate-800/70 bg-slate-950/50">
                  {testResults.approved_metrics.probe_outcomes.map((po) => (
                    <div key={po.probe_index} className="p-2.5 text-xs flex items-center justify-between gap-2">
                      <div>
                        <div className="font-mono text-slate-200">
                          {po.payload_artifact_id} · sha256:{po.payload_sha256_prefix}
                        </div>
                        <div className="text-slate-400">
                          {po.category} · {po.severity_tier}
                        </div>
                      </div>
                      <span
                        className={`font-mono font-semibold whitespace-nowrap ${
                          po.verdict === 'BLOCKED_BY_DEFENSE' ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {po.verdict}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between">
          <span>Model Target: {testStatus.target_model}</span>
          <span className="font-mono text-slate-300">MOCK ADAPTER LABELED</span>
        </div>
      </section>
    </div>
  );
};
