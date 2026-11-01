import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { Check, ChevronLeft, Download, Lock, LogIn, LogOut, Moon, Plus, RefreshCw, Search, SendHorizontal, Shield, Sun } from 'lucide-react';
import LoginDialog from '../components/LoginDialog';
import type {
  AuditEvent, BlueDefenseArtifact, HealthResponse, RedPayloadArtifact, TestResultsResponse, TestStatusResponse, TestSummary,
} from '../types/bayora';
import { api, ApiError, initials, nextAction, ROLES, STATES, timeLabel, type Role } from './api';
import { buildTimeline } from './timeline';
import './chat.css';

const CATEGORIES = ['PROMPT_INJECTION', 'JAILBREAK_ROLEPLAY', 'SYSTEM_PROMPT_EXTRACTION', 'INDIRECT_CONTEXT_POISONING'];
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const RULES = ['INPUT_SANITIZER', 'SYSTEM_PROMPT_GUARD', 'POLICY_CLASSIFIER', 'OUTPUT_REDACTOR', 'ALL_LAYER_SHIELD'];
const label = (s: string) => s.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
const stateClass = (s: string) => s.toLowerCase().replace(/\s+/g, '-');

type Toast = { tone: 'ok' | 'err'; text: string } | null;

export default function ChatApp() {
  const [role, setRole] = useState<Role>(() => (sessionStorage.getItem('bayora_active_role') as Role) || 'EVALUATOR');
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    (localStorage.getItem('bayora_theme') as 'dark' | 'light') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  const [tests, setTests] = useState<TestSummary[]>([]);
  const [viewerRole, setViewerRole] = useState<Role | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<'list' | 'chat'>('list');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<TestStatusResponse | null>(null);
  const [results, setResults] = useState<TestResultsResponse | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [payloads, setPayloads] = useState<RedPayloadArtifact[]>([]);
  const [defenses, setDefenses] = useState<BlueDefenseArtifact[]>([]);
  const [authNeeded, setAuthNeeded] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<Toast>(null);
  const [loaded, setLoaded] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  const effectiveRole = viewerRole ?? role;
  const say = useCallback((tone: 'ok' | 'err', text: string) => setToast({ tone, text }), []);

  useEffect(() => { localStorage.setItem('bayora_theme', theme); }, [theme]);
  useEffect(() => { sessionStorage.setItem('bayora_active_role', role); }, [role]);
  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(t);
  }, [toast]);

  const loadList = useCallback(async () => {
    try {
      const [h, data] = await Promise.all([
        fetch('/api/health').then((r) => (r.ok ? (r.json() as Promise<HealthResponse>) : null)).catch(() => null),
        api<{ tests: TestSummary[]; viewer_role: Role }>('/api/tests', role),
      ]);
      setHealth(h);
      setTests(data.tests || []);
      setViewerRole(data.viewer_role);
      setAuthNeeded(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setAuthNeeded(true);
    } finally {
      setLoaded(true);
    }
  }, [role]);

  const loadDetail = useCallback(async (id: string) => {
    const [s, r, a, p, d] = await Promise.allSettled([
      api<TestStatusResponse>(`/api/tests/${id}/status`, role),
      api<TestResultsResponse>(`/api/tests/${id}/results`, role),
      api<{ events: AuditEvent[] }>(`/api/audit?test_id=${encodeURIComponent(id)}`, role),
      effectiveRole === 'RED_TEAM' ? api<{ payloads: RedPayloadArtifact[] }>(`/api/tests/${id}/payloads`, role) : Promise.resolve({ payloads: [] }),
      effectiveRole === 'BLUE_TEAM' ? api<{ defenses: BlueDefenseArtifact[] }>(`/api/tests/${id}/defenses`, role) : Promise.resolve({ defenses: [] }),
    ]);
    if (s.status === 'fulfilled') setStatus(s.value);
    if (r.status === 'fulfilled') setResults(r.value);
    if (a.status === 'fulfilled') setEvents(a.value.events || []);
    setPayloads(p.status === 'fulfilled' ? p.value.payloads || [] : []);
    setDefenses(d.status === 'fulfilled' ? d.value.defenses || [] : []);
  }, [role, effectiveRole]);

  useEffect(() => { void loadList(); }, [loadList]);
  useEffect(() => { if (selectedId) void loadDetail(selectedId); }, [selectedId, loadDetail]);

  // Gentle live refresh while the tab is visible.
  useEffect(() => {
    const t = window.setInterval(() => {
      if (document.visibilityState !== 'visible' || authNeeded) return;
      void loadList();
      if (selectedId) void loadDetail(selectedId);
    }, 5000);
    return () => window.clearInterval(t);
  }, [authNeeded, selectedId, loadList, loadDetail]);

  const refresh = useCallback(async () => {
    await loadList();
    if (selectedId) await loadDetail(selectedId);
  }, [loadList, loadDetail, selectedId]);

  const timeline = useMemo(
    () => buildTimeline(effectiveRole, events, payloads, defenses, results),
    [effectiveRole, events, payloads, defenses, results],
  );
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }); }, [timeline.length, selectedId]);

  const select = (id: string) => {
    setSelectedId(id);
    setStatus(null); setResults(null); setEvents([]); setPayloads([]); setDefenses([]);
    setView('chat');
  };

  const run = async (fn: () => Promise<string>) => {
    setBusy(true);
    try {
      say('ok', await fn());
    } catch (e) {
      say('err', e instanceof ApiError ? `${e.message} (${e.code})` : 'Something went wrong');
    } finally {
      setBusy(false);
      await refresh();
    }
  };

  const doLogin = async (username: string, credential: string, otp: string): Promise<string | null> => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bayora' },
      body: JSON.stringify({ role, credential, username, otp }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setRole(data.role as Role);
      setShowLogin(false);
      setAuthNeeded(false);
      await loadList();
      return null;
    }
    if (data.code === 'AUTH_OTP_REQUIRED') return 'OTP_REQUIRED';
    return data.message || 'Sign-in failed';
  };

  const signOut = async () => {
    await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-Requested-With': 'bayora' } });
    setViewerRole(null); setTests([]); setSelectedId(null); setView('list'); setAuthNeeded(true); setShowMenu(false);
  };

  const downloadReport = () => {
    setShowMenu(false);
    if (!selectedId) return;
    void run(async () => {
      const data = await api<unknown>(`/api/tests/${selectedId}/report`, role);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url; a.download = `bayora-report-${selectedId}.json`; a.click();
      URL.revokeObjectURL(url);
      return 'Report downloaded';
    });
  };

  const createTest = (name: string, model: string) =>
    run(async () => {
      const t = await api<{ test_id?: string; id?: string }>('/api/tests', role, {
        method: 'POST',
        body: { name, description: 'Isolated adversarial AI safety test run', target_model: model, initial_state: 'Draft' },
      });
      setShowCreate(false);
      const id = t.test_id ?? t.id;
      if (id) select(id);
      return 'Test created';
    });

  const filtered = tests.filter((t) => t.name.toLowerCase().includes(query.toLowerCase()));
  const selected = tests.find((t) => t.id === selectedId) || null;
  const state = status?.state ?? selected?.state ?? 'Draft';
  const canSubmit = state === 'Draft' || state === 'Ready';

  return (
    <div className="bz-root" data-theme={theme} data-view={view}>
      {/* ---------- left: test list ---------- */}
      <aside className="bz-list" aria-label="Tests">
        <header className="bz-bar">
          <div className="bz-brand"><Shield size={20} /> <span>Bayora</span></div>
          <div className="bz-bar-actions">
            <button className="bz-icon" aria-label="Toggle theme" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button className="bz-icon" aria-label="New test" onClick={() => setShowCreate(true)} disabled={effectiveRole === 'BLUE_TEAM'}>
              <Plus size={20} />
            </button>
          </div>
        </header>

        <div className="bz-who">
          <span className={`bz-role bz-role-${effectiveRole.toLowerCase()}`}>{ROLES[effectiveRole].label}</span>
          {viewerRole === null && (
            <select aria-label="Demo role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {(Object.keys(ROLES) as Role[]).map((r) => <option key={r} value={r}>{ROLES[r].label}</option>)}
            </select>
          )}
          <button className="bz-link" onClick={() => setShowLogin(true)}><LogIn size={14} /> Sign in</button>
        </div>

        <label className="bz-search">
          <Search size={16} />
          <input placeholder="Search tests" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>

        <ul className="bz-rows">
          {!loaded && [0, 1, 2].map((i) => <li key={i} className="bz-skeleton" />)}
          {loaded && filtered.length === 0 && (
            <li className="bz-empty">{authNeeded ? 'Sign in to see tests.' : 'No tests yet. Tap + to create one.'}</li>
          )}
          {filtered.map((t) => (
            <li key={t.id}>
              <button className={`bz-row ${t.id === selectedId ? 'is-active' : ''}`} onClick={() => select(t.id)}>
                <span className={`bz-avatar st-${stateClass(t.state)}`}>{initials(t.name)}</span>
                <span className="bz-row-main">
                  <span className="bz-row-top"><strong>{t.name}</strong><time>{timeLabel(t.updated_at)}</time></span>
                  <span className="bz-row-sub">
                    <span className={`bz-pill st-${stateClass(t.state)}`}>{t.state}</span>
                    <span className="bz-count">{t.red_payload_count} payloads · {t.blue_defense_count} defenses</span>
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      {/* ---------- right: conversation ---------- */}
      <main className="bz-chat" aria-label="Conversation">
        {!selected ? (
          <div className="bz-welcome">
            <Shield size={56} />
            <h1>Bayora Systems</h1>
            <p>Adversarial AI safety testing with enforced isolation between Red and Blue teams. Pick a test on the left to open its conversation.</p>
            {health && (
              <span className={`bz-pill ${health.target_adapter.is_mock ? 'st-draft' : 'st-results-released'}`}>
                {health.target_adapter.is_mock ? 'Mock model (simulation)' : 'Live model'}
              </span>
            )}
          </div>
        ) : (
          <>
            <header className="bz-bar bz-chat-bar">
              <button className="bz-icon bz-back" aria-label="Back to tests" onClick={() => setView('list')}><ChevronLeft size={22} /></button>
              <span className={`bz-avatar st-${stateClass(state)}`}>{initials(selected.name)}</span>
              <div className="bz-title">
                <strong>{selected.name}</strong>
                <small>{state} · {selected.target_model} · {selected.is_mock_adapter ? 'MOCK' : 'REAL'}</small>
              </div>
              <div className="bz-bar-actions">
                <button className="bz-icon" aria-label="Refresh" onClick={() => void refresh()}><RefreshCw size={18} /></button>
                <button className="bz-icon" aria-label="Menu" onClick={() => setShowMenu(!showMenu)}>⋮</button>
                {showMenu && (
                  <div className="bz-menu" role="menu">
                    <button role="menuitem" onClick={downloadReport}><Download size={15} /> Download report</button>
                    <button role="menuitem" onClick={() => { setShowMenu(false); setShowLogin(true); }}><LogIn size={15} /> Sign in</button>
                    <button role="menuitem" onClick={() => void signOut()}><LogOut size={15} /> Sign out</button>
                  </div>
                )}
              </div>
            </header>

            <div className="bz-steps" aria-label="Lifecycle">
              {STATES.map((s, i) => (
                <span key={s} className={`bz-step ${STATES.indexOf(state as (typeof STATES)[number]) >= i ? 'is-done' : ''}`}>{s}</span>
              ))}
            </div>

            <div className="bz-stream" role="log" aria-live="polite">
              {timeline.length === 0 && <div className="bz-chip info">Nothing here yet. {canSubmit ? 'Send the first message below.' : ''}</div>}
              {timeline.map((it) => {
                if (it.kind === 'chip') return <div key={it.id} className={`bz-chip ${it.tone}`}>{it.text}</div>;
                if (it.kind === 'result') {
                  const m = it.results.approved_metrics!;
                  return (
                    <div key={it.id} className="bz-result">
                      <div className="bz-score" style={{ ['--p' as string]: `${m.resilience_score}` }}><b>{Math.round(m.resilience_score)}%</b><small>resilience</small></div>
                      <div className="bz-result-body">
                        <strong>Results released</strong>
                        <span>{m.blocked_count} blocked · {m.bypassed_count} bypassed · {m.total_probes} probes</span>
                        <small>{it.results.adapter_label ?? (it.results.is_mock_adapter ? 'Mock adapter (simulation)' : 'Real model')}</small>
                      </div>
                    </div>
                  );
                }
                return (
                  <div key={it.id} className={`bz-msg ${it.side} ${it.team}`}>
                    <div className="bz-bubble">
                      <span className="bz-author">{it.team === 'red' ? 'Red Team' : 'Blue Team'} · {it.author}</span>
                      <strong>{it.title}</strong>
                      {it.body === null ? <span className="bz-locked"><Lock size={13} /> Content hidden by policy</span> : <p>{it.body}</p>}
                      <span className="bz-foot">{it.footer} · {timeLabel(it.time)} {it.side === 'right' && <Check size={13} />}</span>
                    </div>
                  </div>
                );
              })}
              {state === 'Closed' && !results?.results_released && <div className="bz-chip info">Results are withheld until the evaluator releases them.</div>}
              <div ref={endRef} />
            </div>

            <Composer
              role={effectiveRole} state={state} canSubmit={canSubmit} busy={busy}
              onPayload={(c, s, t) => run(async () => {
                const r = await api<{ artifact_id: string }>(`/api/tests/${selectedId}/payloads`, role, { method: 'POST', body: { category: c, severity_tier: s, payload_text: t } });
                return `Payload stored (${r.artifact_id})`;
              })}
              onDefense={(n, r, t) => run(async () => {
                const d = await api<{ artifact_id: string }>(`/api/tests/${selectedId}/defenses`, role, { method: 'POST', body: { defense_name: n, rule_type: r, defense_config_secret: t } });
                return `Defense stored (${d.artifact_id})`;
              })}
              onAdvance={() => run(async () => {
                const a = nextAction(state);
                if (!a) return 'Nothing to do';
                await api(`/api/tests/${selectedId}/${a.path}`, role, { method: 'POST' });
                return `${a.label}: done`;
              })}
            />
          </>
        )}
      </main>

      {authNeeded && (
        <div className="bz-gate" role="alertdialog" aria-label="Sign in required">
          <div className="bz-card">
            <Shield size={36} />
            <h2>Sign in to continue</h2>
            <p>This deployment requires an account. Demo installs can pick a role from the list instead.</p>
            <button className="bz-primary" onClick={() => setShowLogin(true)}>Sign in</button>
          </div>
        </div>
      )}
      {showLogin && <LoginDialog role={role} onClose={() => setShowLogin(false)} onSubmit={doLogin} />}
      {showCreate && <CreateSheet busy={busy} onClose={() => setShowCreate(false)} onCreate={createTest} />}
      {toast && <div className={`bz-toast ${toast.tone}`} role="status">{toast.text}</div>}
    </div>
  );
}

function Composer(props: {
  role: Role; state: string; canSubmit: boolean; busy: boolean;
  onPayload: (c: string, s: string, t: string) => Promise<void>;
  onDefense: (n: string, r: string, t: string) => Promise<void>;
  onAdvance: () => Promise<void>;
}) {
  const [text, setText] = useState('');
  const [cat, setCat] = useState(CATEGORIES[0]);
  const [sev, setSev] = useState('HIGH');
  const [rule, setRule] = useState(RULES[1]);
  const [name, setName] = useState('');

  if (props.role === 'EVALUATOR') {
    const a = nextAction(props.state);
    return (
      <footer className="bz-composer bz-eval">
        {a ? <button className="bz-primary" disabled={props.busy} onClick={() => void props.onAdvance()}>{a.label}</button>
          : <span className="bz-muted">All steps complete. Use the menu to download the report.</span>}
      </footer>
    );
  }
  if (!props.canSubmit) {
    return <footer className="bz-composer"><span className="bz-muted"><Lock size={14} /> Test is “{props.state}”: submissions are locked.</span></footer>;
  }
  const red = props.role === 'RED_TEAM';
  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return;
    if (red) await props.onPayload(cat, sev, text.trim());
    else await props.onDefense(name.trim() || 'Defense rule', rule, text.trim());
    setText('');
  };
  return (
    <footer className="bz-composer">
      <form onSubmit={(e) => void send(e)}>
        <div className="bz-opts">
          {red ? (
            <>
              <select aria-label="Category" value={cat} onChange={(e) => setCat(e.target.value)}>{CATEGORIES.map((c) => <option key={c} value={c}>{label(c)}</option>)}</select>
              <select aria-label="Severity" value={sev} onChange={(e) => setSev(e.target.value)}>{SEVERITIES.map((s) => <option key={s} value={s}>{label(s)}</option>)}</select>
            </>
          ) : (
            <>
              <input aria-label="Defense name" placeholder="Rule name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
              <select aria-label="Rule type" value={rule} onChange={(e) => setRule(e.target.value)}>{RULES.map((r) => <option key={r} value={r}>{label(r)}</option>)}</select>
            </>
          )}
        </div>
        <div className="bz-input">
          <textarea
            aria-label={red ? 'Attack payload' : 'Defense rule'} rows={1} value={text} maxLength={2000}
            placeholder={red ? 'Type an attack payload…' : 'Type a secret defense rule…'}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form?.requestSubmit(); } }}
          />
          <button className="bz-send" type="submit" disabled={props.busy || !text.trim()} aria-label="Send"><SendHorizontal size={20} /></button>
        </div>
      </form>
    </footer>
  );
}

function CreateSheet(props: { busy: boolean; onClose: () => void; onCreate: (name: string, model: string) => Promise<void> }) {
  const [name, setName] = useState('');
  const [model, setModel] = useState('target-model-v1');
  return (
    <div className="bz-gate" onClick={props.onClose}>
      <form className="bz-sheet" onClick={(e) => e.stopPropagation()} onSubmit={(e) => { e.preventDefault(); void props.onCreate(name.trim(), model.trim()); }}>
        <h2>New test</h2>
        <input placeholder="Test name (min 3 characters)" value={name} onChange={(e) => setName(e.target.value)} minLength={3} maxLength={120} required autoFocus />
        <input placeholder="Target model" value={model} onChange={(e) => setModel(e.target.value)} required />
        <div className="bz-sheet-actions">
          <button type="button" className="bz-ghost" onClick={props.onClose}>Cancel</button>
          <button type="submit" className="bz-primary" disabled={props.busy}>Create</button>
        </div>
      </form>
    </div>
  );
}
