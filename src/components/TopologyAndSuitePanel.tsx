import React from 'react';
import { HealthResponse, SecuritySuiteResponse } from '../types/bayora';
import { Play, CheckCircle2, AlertTriangle, Server } from 'lucide-react';

interface TopologyAndSuitePanelProps {
  health: HealthResponse | null;
  suiteResult: SecuritySuiteResponse | null;
  runningSuite: boolean;
  onRunSecuritySuite: () => void;
  onProbeDirectPeerNetwork: () => void;
}

export const TopologyAndSuitePanel: React.FC<TopologyAndSuitePanelProps> = ({
  health,
  suiteResult,
  runningSuite,
  onRunSecuritySuite,
  onProbeDirectPeerNetwork,
}) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
      {/* Docker Network Isolation Topology (5 cols) */}
      <section
        aria-label="Docker Network Segmentation and Container Hardening"
        className="lg:col-span-5 border border-slate-800 bg-slate-900/60 p-5 rounded-lg flex flex-col justify-between space-y-4"
      >
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <div className="text-xs text-slate-400">
              <span>Container &amp; Network Isolation</span>
              <span className="mx-2" aria-hidden="true">·</span>
              <span>compose.yaml Hardened</span>
            </div>
            <h3 className="text-base font-semibold text-white mt-0.5 flex items-center gap-2">
              <Server className="w-4 h-4 text-sky-400" />
              <span>3-Network Topology &amp; Dev Machine Health</span>
            </h3>
          </div>

          <div className="space-y-3 text-xs">
            <div className="border border-slate-800 bg-slate-950/60 p-3.5 rounded space-y-1">
              <div className="flex items-center justify-between font-mono">
                <span className="text-rose-300 font-semibold">1. red-worker (UID 10001:10001)</span>
                <span className="text-emerald-400">{health?.dev_machines.red_team_node.status || 'ready'}</span>
              </div>
              <div className="text-slate-400">
                Network: <code className="text-slate-200">red-net (internal: true)</code> · Direct Blue Access:{' '}
                <span className="text-rose-400 font-mono">BLOCKED</span>
              </div>
            </div>

            <div className="border border-slate-800 bg-slate-950/60 p-3.5 rounded space-y-1">
              <div className="flex items-center justify-between font-mono">
                <span className="text-sky-300 font-semibold">2. blue-worker (UID 10002:10002)</span>
                <span className="text-emerald-400">{health?.dev_machines.blue_team_node.status || 'ready'}</span>
              </div>
              <div className="text-slate-400">
                Network: <code className="text-slate-200">blue-net (internal: true)</code> · Direct Red Access:{' '}
                <span className="text-rose-400 font-mono">BLOCKED</span>
              </div>
            </div>

            <div className="border border-slate-800 bg-slate-950/60 p-3.5 rounded space-y-1">
              <div className="flex items-center justify-between font-mono">
                <span className="text-emerald-300 font-semibold">3. control-plane &amp; target-adapter</span>
                <span className="text-emerald-400">{health?.dev_machines.evaluator_control_plane.status || 'ready'}</span>
              </div>
              <div className="text-slate-400">
                Network: <code className="text-slate-200">control-net</code> · Mediates all authorized calls · Read-only rootfs, <code className="text-slate-200">cap_drop: [ALL]</code>
              </div>
            </div>
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800 flex items-center justify-between gap-3">
          <span className="text-xs text-slate-400">
            Verify RUNTIME-01 peer block:
          </span>
          <button
            type="button"
            onClick={onProbeDirectPeerNetwork}
            className="px-3.5 py-2 text-xs font-medium rounded-md border border-rose-800/80 bg-rose-950/40 text-rose-200 hover:bg-rose-900/50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Simulate Direct Red→Blue Call
          </button>
        </div>
      </section>

      {/* Live Automated Security Evidence Suite Runner (7 cols) */}
      <section
        aria-label="Automated Hackathon Security Test Suite"
        className="lg:col-span-7 border border-slate-800 bg-slate-900/60 p-5 rounded-lg flex flex-col justify-between space-y-4"
      >
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <div className="text-xs text-slate-400">
                <span>Live Backend Verification Runner</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>backend/tests/test_security_suite.py</span>
              </div>
              <h3 className="text-base font-semibold text-white mt-0.5">
                Automated Security &amp; Isolation Evidence Suite (11 Tests)
              </h3>
            </div>

            <button
              type="button"
              onClick={onRunSecuritySuite}
              disabled={runningSuite}
              className="px-4 py-2 text-xs font-medium rounded-md bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{runningSuite ? 'Running Python Unittest Suite...' : 'Run All 11 Security Tests Live'}</span>
            </button>
          </div>

          {!suiteResult ? (
            <div className="text-xs text-slate-400 py-6 text-center border border-dashed border-slate-800 rounded space-y-2">
              <p>Click &ldquo;Run All 11 Security Tests Live&rdquo; to execute the Python backend test suite against an isolated in-memory SQLite instance.</p>
              <p className="font-mono text-slate-500">
                Covers SEC-01, SEC-02, SEC-03, STATE-01, DATA-01, MODEL-01, AUDIT-01, RUNTIME-01, POS-01, POS-02, DOCKER-HARDENING
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono bg-slate-950/70 border border-slate-800 px-3.5 py-2 rounded">
                <span className="text-emerald-400 font-semibold">
                  RESULT: {suiteResult.passed}/{suiteResult.total} TESTS PASSED
                </span>
                <span className="text-slate-400">
                  Executed {suiteResult.executed_at.replace('T', ' ').slice(0, 19)}Z
                </span>
              </div>

              <div className="overflow-x-auto border border-slate-800 rounded max-h-60 overflow-y-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-950 text-slate-400">
                      <th className="py-2 px-3 font-medium">Test Function</th>
                      <th className="py-2 px-3 font-medium">Status</th>
                      <th className="py-2 px-3 font-medium text-right">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70 font-mono">
                    {suiteResult.results.map((r) => (
                      <tr key={r.test_name} className="hover:bg-slate-800/30">
                        <td className="py-2 px-3 text-slate-200">{r.test_name}</td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          {r.status === 'PASS' ? (
                            <span className="text-emerald-400 flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                            </span>
                          ) : (
                            <span className="text-rose-400 flex items-center gap-1">
                              <AlertTriangle className="w-3.5 h-3.5" /> FAIL
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right text-slate-400 tabular-nums">{r.duration_ms} ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
