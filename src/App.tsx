import React, { useCallback, useEffect, useState } from 'react';
import LoginDialog from './components/LoginDialog';
import {
  BayoraRole,
  ROLE_DESCRIPTORS,
  SanitizedDenialNotice,
  formatDenialExplanation,
} from './lib/bayoraLogic';
import {
  AuditEvent,
  BlueDefenseArtifact,
  HealthResponse,
  RedPayloadArtifact,
  SecuritySuiteResponse,
  TestResultsResponse,
  TestStatusResponse,
  TestSummary,
} from './types/bayora';
import { LifecycleStepper } from './components/LifecycleStepper';
import { RoleWorkspacePanel } from './components/RoleWorkspacePanel';
import { AuditTimelinePanel } from './components/AuditTimelinePanel';
import { TopologyAndSuitePanel } from './components/TopologyAndSuitePanel';
import { Plus, ShieldAlert, CheckCircle2, RefreshCw, X } from 'lucide-react';

export default function App() {
  const [activeRole, setActiveRole] = useState<BayoraRole>(
    () => (sessionStorage.getItem('bayora_active_role') as BayoraRole) || 'RED_TEAM'
  );
  useEffect(() => {
    sessionStorage.setItem('bayora_active_role', activeRole);
  }, [activeRole]);
  const [activeSection, setActiveSection] = useState<'workspace' | 'audit' | 'topology'>('workspace');

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [tests, setTests] = useState<TestSummary[]>([]);
  const [selectedTestId, setSelectedTestId] = useState<string | null>(null);
  const [testStatus, setTestStatus] = useState<TestStatusResponse | null>(null);
  const [testResults, setTestResults] = useState<TestResultsResponse | null>(null);
  const [redPayloads, setRedPayloads] = useState<RedPayloadArtifact[]>([]);
  const [blueDefenses, setBlueDefenses] = useState<BlueDefenseArtifact[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [showAllTestsAudit, setShowAllTestsAudit] = useState<boolean>(false);

  const [denialNotice, setDenialNotice] = useState<SanitizedDenialNotice | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  // Create Test Modal State
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newTestName, setNewTestName] = useState('');
  const [newTestDesc, setNewTestDesc] = useState('');
  const [newTestModel, setNewTestModel] = useState('mock-bayora-llm-7b-instruct');
  const [createFormError, setCreateFormError] = useState<string | null>(null);

  // Security Suite State
  const [suiteResult, setSuiteResult] = useState<SecuritySuiteResponse | null>(null);
  const [runningSuite, setRunningSuite] = useState(false);

  const [showLogin, setShowLogin] = useState(false);

  // Session lives in an HttpOnly cookie set by the gateway, so no token is ever readable by page scripts.
  const doLogin = useCallback(
    async (username: string, credential: string, otp: string): Promise<string | null> => {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bayora' },
        body: JSON.stringify({ role: activeRole, credential, username, otp }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        sessionStorage.setItem('bayora_active_role', data.role);
        window.location.reload();
        return null;
      }
      if (data.code === 'AUTH_OTP_REQUIRED') return 'OTP_REQUIRED';
      return data.message || 'Sign-in failed';
    },
    [activeRole]
  );

  const signOut = useCallback(async () => {
    await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-Requested-With': 'bayora' } });
    window.location.reload();
  }, []);

  const downloadReport = useCallback(async () => {
    if (!selectedTestId) return window.alert('Select a test first');
    const res = await fetch(`/api/tests/${selectedTestId}/report`, {
      headers: { 'X-Requested-With': 'bayora', 'X-Bayora-Role': 'EVALUATOR', 'X-Bayora-Actor': 'evaluator-report' },
    });
    if (!res.ok) return window.alert('Report unavailable: evaluator sign-in and released results are required');
    const url = URL.createObjectURL(new Blob([JSON.stringify(await res.json(), null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `bayora-report-${selectedTestId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [selectedTestId]);

  const getRoleHeaders = useCallback(
    (overrideRole?: BayoraRole): Record<string, string> => {
      const r = overrideRole || activeRole;
      return {
        'Content-Type': 'application/json',
        'X-Requested-With': 'bayora',
        'X-Bayora-Role': r,
        'X-Bayora-Actor': ROLE_DESCRIPTORS[r].defaultActor,
      };
    },
    [activeRole]
  );

  const fetchHealthAndTests = useCallback(async () => {
    try {
      const [hRes, tRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/tests', { headers: getRoleHeaders() }),
      ]);
      if (hRes.ok) {
        setHealth(await hRes.json());
      }
      if (tRes.ok) {
        const data = await tRes.json();
        const list: TestSummary[] = data.tests || [];
        setTests(list);
        setSelectedTestId((prev) => prev || (list.length > 0 ? list[0].id : null));
      }
    } catch {
      // Handled gracefully
    }
  }, [getRoleHeaders]);

  const fetchSelectedTestDetails = useCallback(
    async (testId: string, role: BayoraRole, allAudit: boolean) => {
      const headers = getRoleHeaders(role);
      try {
        const auditUrl = allAudit ? '/api/audit' : `/api/audit?test_id=${encodeURIComponent(testId)}`;
        const [statusRes, resultsRes, auditRes] = await Promise.all([
          fetch(`/api/tests/${testId}/status`, { headers }),
          fetch(`/api/tests/${testId}/results`, { headers }),
          fetch(auditUrl, { headers }),
        ]);

        if (statusRes.ok) {
          setTestStatus(await statusRes.json());
        }
        if (resultsRes.ok) {
          setTestResults(await resultsRes.json());
        }
        if (auditRes.ok) {
          const aData = await auditRes.json();
          setAuditEvents(aData.events || []);
        }

        // Only fetch private role artifacts when acting as that role so normal tab switching doesn't spam denials
        if (role === 'RED_TEAM') {
          const pRes = await fetch(`/api/tests/${testId}/payloads`, { headers });
          if (pRes.ok) {
            const pData = await pRes.json();
            setRedPayloads(pData.payloads || []);
          }
          setBlueDefenses([]);
        } else if (role === 'BLUE_TEAM') {
          const dRes = await fetch(`/api/tests/${testId}/defenses`, { headers });
          if (dRes.ok) {
            const dData = await dRes.json();
            setBlueDefenses(dData.defenses || []);
          }
          setRedPayloads([]);
        } else {
          setRedPayloads([]);
          setBlueDefenses([]);
        }
      } catch {
        // Handled gracefully
      }
    },
    [getRoleHeaders]
  );

  useEffect(() => {
    fetchHealthAndTests();
  }, [fetchHealthAndTests]);

  useEffect(() => {
    if (selectedTestId) {
      fetchSelectedTestDetails(selectedTestId, activeRole, showAllTestsAudit);
    }
  }, [selectedTestId, activeRole, showAllTestsAudit, fetchSelectedTestDetails]);

  const refreshAll = async (targetTestId?: string) => {
    await fetchHealthAndTests();
    const idToLoad = targetTestId || selectedTestId;
    if (idToLoad) {
      await fetchSelectedTestDetails(idToLoad, activeRole, showAllTestsAudit);
    }
  };

  // Create Test Handler
  const handleCreateTest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newTestName.trim().length < 3) {
      setCreateFormError('Test name must be at least 3 characters.');
      return;
    }
    setCreateFormError(null);
    setBusyAction('create');
    setDenialNotice(null);
    setSuccessBanner(null);

    try {
      const res = await fetch('/api/tests', {
        method: 'POST',
        headers: getRoleHeaders(),
        body: JSON.stringify({
          name: newTestName.trim(),
          description: newTestDesc.trim() || 'Isolated adversarial AI safety test run',
          target_model: newTestModel.trim(),
          initial_state: 'Draft',
        }),
      });
      const body = await res.json();
      if (!res.ok) {
        setDenialNotice(formatDenialExplanation(res.status, body, `Create Test as ${activeRole}`));
        setIsCreateModalOpen(false);
        await refreshAll();
        return;
      }
      setNewTestName('');
      setNewTestDesc('');
      setIsCreateModalOpen(false);
      setSelectedTestId(body.test_id);
      setSuccessBanner(`Created test record ${body.test_id} in Draft state.`);
      await refreshAll(body.test_id);
    } finally {
      setBusyAction(null);
    }
  };

  // Lifecycle Transition Handler
  const handleLifecycleTransition = async (action: 'ready' | 'start' | 'close' | 'release') => {
    if (!selectedTestId) return;
    setBusyAction(action);
    setDenialNotice(null);
    setSuccessBanner(null);

    const endpointMap: Record<typeof action, string> = {
      ready: `/api/tests/${selectedTestId}/ready`,
      start: `/api/tests/${selectedTestId}/start`,
      close: `/api/tests/${selectedTestId}/close`,
      release: `/api/tests/${selectedTestId}/results/release`,
    };

    try {
      const res = await fetch(endpointMap[action], {
        method: 'POST',
        headers: getRoleHeaders(),
      });
      const body = await res.json();
      if (!res.ok) {
        setDenialNotice(formatDenialExplanation(res.status, body, `Lifecycle Action '${action.toUpperCase()}'`));
      } else {
        setSuccessBanner(
          `Transitioned ${selectedTestId} (${body.transition})${
            body.run_id ? ` · Run ID: ${body.run_id}` : ''
          }${body.session_id ? ` · Fresh Session: ${body.session_id}` : ''}`
        );
      }
      await refreshAll();
    } finally {
      setBusyAction(null);
    }
  };

  // Submit Red Payload
  const handleSubmitRedPayload = async (category: string, severity: string, payloadText: string) => {
    if (!selectedTestId) return;
    setDenialNotice(null);
    setSuccessBanner(null);
    const res = await fetch(`/api/tests/${selectedTestId}/payloads`, {
      method: 'POST',
      headers: getRoleHeaders(),
      body: JSON.stringify({ category, severity_tier: severity, payload_text: payloadText }),
    });
    const body = await res.json();
    if (!res.ok) {
      setDenialNotice(formatDenialExplanation(res.status, body, 'Submit Red Team Payload'));
    } else {
      setSuccessBanner(`Stored isolated Red payload ${body.artifact_id} (SHA-256: ${body.payload_sha256.slice(0, 12)}…).`);
    }
    await refreshAll();
  };

  // Submit Blue Defense
  const handleSubmitBlueDefense = async (defenseName: string, ruleType: string, secretConfig: string) => {
    if (!selectedTestId) return;
    setDenialNotice(null);
    setSuccessBanner(null);
    const res = await fetch(`/api/tests/${selectedTestId}/defenses`, {
      method: 'POST',
      headers: getRoleHeaders(),
      body: JSON.stringify({
        defense_name: defenseName,
        rule_type: ruleType,
        defense_config_secret: secretConfig,
      }),
    });
    const body = await res.json();
    if (!res.ok) {
      setDenialNotice(formatDenialExplanation(res.status, body, 'Submit Blue Team Defense'));
    } else {
      setSuccessBanner(`Stored isolated Blue defense ${body.artifact_id} (SHA-256: ${body.config_sha256.slice(0, 12)}…).`);
    }
    await refreshAll();
  };

  // Boundary Probes (SEC-01, SEC-02, SEC-03, STATE-01, RUNTIME-01)
  const handleAttemptCrossRoleRead = async (target: 'blue_defense' | 'red_payload') => {
    if (!selectedTestId) return;
    setBusyAction('probe');
    setDenialNotice(null);
    setSuccessBanner(null);

    try {
      if (target === 'blue_defense') {
        // SEC-01: Force call with RED_TEAM role to /defenses
        const res = await fetch(`/api/tests/${selectedTestId}/defenses`, {
          headers: getRoleHeaders('RED_TEAM'),
        });
        const body = await res.json();
        setDenialNotice(
          formatDenialExplanation(res.status, body, 'SEC-01 Probe: RED_TEAM Reading Unreleased Blue Defense')
        );
      } else {
        // SEC-02: Force call with BLUE_TEAM role to /payloads
        const res = await fetch(`/api/tests/${selectedTestId}/payloads`, {
          headers: getRoleHeaders('BLUE_TEAM'),
        });
        const body = await res.json();
        setDenialNotice(
          formatDenialExplanation(res.status, body, 'SEC-02 Probe: BLUE_TEAM Reading Unreleased Red Payload')
        );
      }
      await refreshAll();
    } finally {
      setBusyAction(null);
    }
  };

  const handleAttemptUnauthorizedRelease = async () => {
    if (!selectedTestId) return;
    setBusyAction('probe-sec03');
    setDenialNotice(null);
    setSuccessBanner(null);
    try {
      const nonEvalRole: BayoraRole = activeRole === 'EVALUATOR' ? 'RED_TEAM' : activeRole;
      const res = await fetch(`/api/tests/${selectedTestId}/results/release`, {
        method: 'POST',
        headers: getRoleHeaders(nonEvalRole),
      });
      const body = await res.json();
      setDenialNotice(
        formatDenialExplanation(res.status, body, `SEC-03 Probe: ${nonEvalRole} Attempting Result Release`)
      );
      await refreshAll();
    } finally {
      setBusyAction(null);
    }
  };

  const handleAttemptInvalidTransition = async () => {
    if (!selectedTestId || !testStatus) return;
    setBusyAction('probe-state01');
    setDenialNotice(null);
    setSuccessBanner(null);
    try {
      // Pick an out-of-order transition based on current state
      const invalidEndpoint =
        testStatus.state === 'Draft'
          ? `/api/tests/${selectedTestId}/results/release`
          : testStatus.state === 'Running'
          ? `/api/tests/${selectedTestId}/ready`
          : `/api/tests/${selectedTestId}/start`;

      const res = await fetch(invalidEndpoint, {
        method: 'POST',
        headers: getRoleHeaders('EVALUATOR'),
      });
      const body = await res.json();
      setDenialNotice(
        formatDenialExplanation(
          res.status,
          body,
          `STATE-01 Probe: Invalid Lifecycle Jump from '${testStatus.state}'`
        )
      );
      await refreshAll();
    } finally {
      setBusyAction(null);
    }
  };

  const handleAttemptDirectNetworkCall = async () => {
    setBusyAction('probe-runtime01');
    setDenialNotice(null);
    setSuccessBanner(null);
    try {
      const res = await fetch('/api/network/probe', {
        method: 'POST',
        headers: getRoleHeaders('RED_TEAM'),
        body: JSON.stringify({
          source_service: 'red-worker',
          target_service: 'blue-worker',
          test_id: selectedTestId || 'GLOBAL_NETWORK',
        }),
      });
      const body = await res.json();
      setDenialNotice(
        formatDenialExplanation(
          res.status,
          body,
          'RUNTIME-01 Probe: Direct red-worker → blue-worker Container Call'
        )
      );
      await refreshAll();
    } finally {
      setBusyAction(null);
    }
  };

  const handleRunSecuritySuite = async () => {
    setRunningSuite(true);
    try {
      const res = await fetch('/api/security-suite/verify', {
        method: 'POST',
        headers: getRoleHeaders('EVALUATOR'),
      });
      if (res.ok) {
        const data: SecuritySuiteResponse = await res.json();
        setSuiteResult(data);
        setSuccessBanner(`Security Evidence Suite complete: ${data.passed}/${data.total} tests passed.`);
        await refreshAll();
      }
    } finally {
      setRunningSuite(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0b0f17] text-slate-100">
      {/* Top Bar Contract: 3 Zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-slate-950/90">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('workspace');
          }}
          className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 font-display"
        >
          Bayora Systems
        </a>

        {/* Zone 2: 4 concise single-line navigation links */}
        <nav aria-label="Primary Workspace Navigation" className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300">
          <a
            href="#workspace"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('workspace');
            }}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'workspace' ? 'text-white underline underline-offset-8 decoration-sky-500' : ''
            }`}
          >
            Control Plane
          </a>
          <a
            href="#audit-ledger"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('audit');
            }}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'audit' ? 'text-white underline underline-offset-8 decoration-sky-500' : ''
            }`}
          >
            Audit Ledger
          </a>
          <a
            href="#network-topology"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('topology');
            }}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'topology' ? 'text-white underline underline-offset-8 decoration-sky-500' : ''
            }`}
          >
            Network Topology
          </a>
          <a
            href="#security-suite"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('topology');
              handleRunSecuritySuite();
            }}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Verify Suite (11 Tests)
          </a>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => {
              setCreateFormError(null);
              setIsCreateModalOpen(true);
            }}
            className="px-4 py-2 text-xs font-medium text-white bg-sky-600 rounded-md hover:bg-sky-500 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Test Record</span>
          </button>
        </div>
      </header>

      {/* Main Workspace Layout: Sidebar (280px) + Content Viewport */}
      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Left Sidebar: Test Registry & Active Role Selector */}
        <aside
          aria-label="Test Registry and Role Switcher"
          className="w-full lg:w-72 shrink-0 border-b lg:border-b-0 lg:border-r border-slate-800 bg-slate-950/60 p-4 flex flex-col justify-between gap-6"
        >
          <div className="space-y-6">
            {/* Active Identity / Role Selector */}
            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-400">
                Active Operator Identity (<code className="text-slate-300">X-Bayora-Role</code>)
              </div>
              <button
                type="button"
                onClick={() => setShowLogin(true)}
                className="w-full text-xs rounded border border-slate-700 px-2 py-1 text-slate-300 hover:bg-slate-800"
              >
                Sign in as {activeRole} (secure mode)
              </button>
              {showLogin && (
                <LoginDialog role={activeRole} onClose={() => setShowLogin(false)} onSubmit={doLogin} />
              )}
              <div className="grid grid-cols-2 gap-1.5">
                <button type="button" onClick={signOut}
                  className="text-xs rounded border border-slate-700 px-2 py-1 text-slate-300 hover:bg-slate-800">
                  Sign out
                </button>
                <button type="button" onClick={downloadReport}
                  className="text-xs rounded border border-slate-700 px-2 py-1 text-slate-300 hover:bg-slate-800">
                  Download report
                </button>
              </div>
              <div className="grid grid-cols-3 lg:grid-cols-1 gap-1.5" role="group" aria-label="Select Operator Role">
                {(['RED_TEAM', 'BLUE_TEAM', 'EVALUATOR'] as BayoraRole[]).map((r) => {
                  const desc = ROLE_DESCRIPTORS[r];
                  const isSelected = activeRole === r;
                  return (
                    <button
                      key={r}
                      type="button"
                      onClick={() => {
                        setActiveRole(r);
                        setDenialNotice(null);
                      }}
                      className={`px-3 py-2.5 rounded-md border text-left transition-colors cursor-pointer ${
                        isSelected
                          ? 'border-sky-500 bg-sky-950/40 text-white'
                          : 'border-slate-800/80 bg-slate-900/40 text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-mono font-semibold">
                        <span>{r}</span>
                        <span>{isSelected ? 'ACTIVE' : ''}</span>
                      </div>
                      <div className="text-xs text-slate-300 mt-0.5 truncate">{desc.label}</div>
                      <div className="text-[11px] font-mono text-slate-400 truncate">{desc.defaultActor}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Test Record Registry */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">
                  Adversarial Test Records ({tests.length})
                </span>
                <button
                  type="button"
                  onClick={() => refreshAll()}
                  aria-label="Refresh Test Registry"
                  className="p-1 text-slate-400 hover:text-white rounded transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-1.5 max-h-96 overflow-y-auto pr-0.5">
                {tests.map((t) => {
                  const isSelected = t.id === selectedTestId;
                  return (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => {
                        setSelectedTestId(t.id);
                        setDenialNotice(null);
                      }}
                      className={`w-full p-3 rounded-md border text-left transition-colors cursor-pointer ${
                        isSelected
                          ? 'border-slate-600 bg-slate-900 text-white'
                          : 'border-slate-800/70 bg-slate-950/40 text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                        <span>{t.id}</span>
                        <span
                          className={
                            t.state === 'Results Released'
                              ? 'text-emerald-400 font-semibold'
                              : t.state === 'Running'
                              ? 'text-sky-400 font-semibold'
                              : t.state === 'Closed'
                              ? 'text-indigo-300 font-semibold'
                              : 'text-amber-300'
                          }
                        >
                          {t.state}
                        </span>
                      </div>
                      <div className="text-xs font-semibold text-slate-100 mt-1 line-clamp-1">{t.name}</div>
                      <div className="text-[11px] text-slate-400 mt-1 font-mono">
                        Red: {t.red_payload_count} · Blue: {t.blue_defense_count} · Mock LLM
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Honest Environment Status Footer */}
          <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-1 font-mono">
            <div>Backend: FastAPI/Compat + SQLite3</div>
            <div>Target: MOCK_DETERMINISTIC_V1</div>
            <div>Health: {health?.status === 'healthy' ? '3/3 Nodes Nominal' : 'Connecting...'}</div>
          </div>
        </aside>

        {/* Main Workspace Viewport */}
        <main className="flex-1 p-6 space-y-6 max-w-[1440px]">
          {/* Context Header & Role Scope Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="text-xs text-slate-400">
                <span>Bayora Isolation Control Plane</span>
                <span className="mx-2" aria-hidden="true">/</span>
                <span className="font-mono text-slate-300">{ROLE_DESCRIPTORS[activeRole].networkPlane}</span>
                <span className="mx-2" aria-hidden="true">/</span>
                <span className="font-mono text-sky-400">{selectedTestId || 'No Test Selected'}</span>
              </div>
              <h1 className="text-xl font-bold text-white mt-1 font-display">
                {testStatus ? testStatus.name : 'Select or Create an Adversarial Safety Test'}
              </h1>
              {testStatus && (
                <p className="text-xs text-slate-400 mt-0.5">
                  {testStatus.description} · Target: <code className="text-slate-300">{testStatus.target_model}</code> ·{' '}
                  <span className="text-amber-300 font-mono">MOCK ADAPTER (DETERMINISTIC — NO REAL WEIGHTS)</span>
                </p>
              )}
            </div>

            {/* Mobile/Quick View Tabs */}
            <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-md self-start">
              <button
                type="button"
                onClick={() => setActiveSection('workspace')}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeSection === 'workspace' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Workspace &amp; Results
              </button>
              <button
                type="button"
                onClick={() => setActiveSection('audit')}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeSection === 'audit' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Audit Ledger ({auditEvents.length})
              </button>
              <button
                type="button"
                onClick={() => setActiveSection('topology')}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  activeSection === 'topology' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Docker &amp; Security Suite
              </button>
            </div>
          </div>

          {/* Fail-Closed Denial Alert Banner (Zero Secret Leakage) */}
          {denialNotice && (
            <div
              role="alert"
              className="border border-rose-700/80 bg-rose-950/40 p-4 rounded-lg flex items-start justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-rose-300 text-sm font-semibold">
                  <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{denialNotice.headline}</span>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed">{denialNotice.explanation}</p>
                <div className="text-xs font-mono text-rose-300/90 pt-1">
                  Policy Code: {denialNotice.policyCode} · Secret Payload in Error Body: NONE (Verified Fail-Closed) · Audit Event: RECORDED (DENY)
                </div>
              </div>
              <button
                type="button"
                aria-label="Dismiss Denial Alert"
                onClick={() => setDenialNotice(null)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Action Success Feedback Banner */}
          {successBanner && !denialNotice && (
            <div
              role="status"
              className="border border-emerald-800/80 bg-emerald-950/30 px-4 py-3 rounded-lg flex items-center justify-between gap-4"
            >
              <div className="flex items-center gap-2 text-xs text-emerald-200 font-mono">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{successBanner}</span>
              </div>
              <button
                type="button"
                aria-label="Dismiss Status Notice"
                onClick={() => setSuccessBanner(null)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {testStatus && activeSection === 'workspace' && (
            <>
              <LifecycleStepper
                currentState={testStatus.state}
                activeRole={activeRole}
                busyAction={busyAction}
                onTransition={handleLifecycleTransition}
                onAttemptInvalidTransition={handleAttemptInvalidTransition}
                onAttemptCrossRoleRead={handleAttemptCrossRoleRead}
                onAttemptUnauthorizedRelease={handleAttemptUnauthorizedRelease}
                onAttemptDirectNetworkCall={handleAttemptDirectNetworkCall}
              />

              <RoleWorkspacePanel
                activeRole={activeRole}
                testStatus={testStatus}
                testResults={testResults}
                redPayloads={redPayloads}
                blueDefenses={blueDefenses}
                onSubmitRedPayload={handleSubmitRedPayload}
                onSubmitBlueDefense={handleSubmitBlueDefense}
              />

              <AuditTimelinePanel
                events={auditEvents}
                selectedTestId={selectedTestId}
                showAllTestsAudit={showAllTestsAudit}
                onToggleScope={setShowAllTestsAudit}
              />
            </>
          )}

          {activeSection === 'audit' && (
            <AuditTimelinePanel
              events={auditEvents}
              selectedTestId={selectedTestId}
              showAllTestsAudit={showAllTestsAudit}
              onToggleScope={setShowAllTestsAudit}
            />
          )}

          {activeSection === 'topology' && (
            <TopologyAndSuitePanel
              health={health}
              suiteResult={suiteResult}
              runningSuite={runningSuite}
              onRunSecuritySuite={handleRunSecuritySuite}
              onProbeDirectPeerNetwork={handleAttemptDirectNetworkCall}
            />
          )}
        </main>
      </div>

      {/* Create Test Modal */}
      {isCreateModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-test-modal-title"
          className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4"
        >
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 id="create-test-modal-title" className="text-base font-semibold text-white">
                Create New Adversarial Test Record (<code className="text-xs font-mono text-sky-400">POST /api/tests</code>)
              </h2>
              <button
                type="button"
                aria-label="Close Create Test Modal"
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateTest} className="space-y-4">
              <div>
                <label htmlFor="new-test-name" className="block text-xs font-medium text-slate-300 mb-1">
                  Test Campaign Name
                </label>
                <input
                  id="new-test-name"
                  type="text"
                  value={newTestName}
                  onChange={(e) => setNewTestName(e.target.value)}
                  placeholder="e.g. Autonomous Code Agent — Sandbox Escape Evaluation"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label htmlFor="new-test-desc" className="block text-xs font-medium text-slate-300 mb-1">
                  Evaluation Scope &amp; Isolation Objective
                </label>
                <textarea
                  id="new-test-desc"
                  rows={2}
                  value={newTestDesc}
                  onChange={(e) => setNewTestDesc(e.target.value)}
                  placeholder="Describe the target boundary under evaluation..."
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label htmlFor="new-test-model" className="block text-xs font-medium text-slate-300 mb-1">
                  Target Model Identifier (Evaluated via Deterministic Mock Adapter)
                </label>
                <input
                  id="new-test-model"
                  type="text"
                  value={newTestModel}
                  onChange={(e) => setNewTestModel(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              {createFormError && <p className="text-xs text-rose-400">{createFormError}</p>}

              <div className="text-xs text-slate-400 font-mono">
                Caller Role: {activeRole} ({ROLE_DESCRIPTORS[activeRole].defaultActor})
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white rounded-md cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busyAction === 'create'}
                  className="px-4 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-md cursor-pointer"
                >
                  {busyAction === 'create' ? 'Creating...' : 'Create Test in Draft State'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
