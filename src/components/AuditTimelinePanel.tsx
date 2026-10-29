import React, { useState } from 'react';
import { AuditEvent } from '../types/bayora';

interface AuditTimelinePanelProps {
  events: AuditEvent[];
  selectedTestId: string | null;
  showAllTestsAudit: boolean;
  onToggleScope: (showAll: boolean) => void;
}

export const AuditTimelinePanel: React.FC<AuditTimelinePanelProps> = ({
  events,
  selectedTestId,
  showAllTestsAudit,
  onToggleScope,
}) => {
  const [decisionFilter, setDecisionFilter] = useState<'ALL' | 'DENY' | 'ALLOW'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredEvents = events.filter((ev) => {
    if (decisionFilter !== 'ALL' && ev.decision !== decisionFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        ev.action.toLowerCase().includes(q) ||
        ev.role.toLowerCase().includes(q) ||
        ev.resource.toLowerCase().includes(q) ||
        ev.reason_code.toLowerCase().includes(q) ||
        (ev.state_transition || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const denyCount = events.filter((e) => e.decision === 'DENY').length;
  const allowCount = events.filter((e) => e.decision === 'ALLOW').length;

  return (
    <section
      aria-label="Immutable Security Audit Evidence Timeline"
      className="border border-slate-800 bg-slate-900/60 p-5 rounded-lg space-y-4"
    >
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="text-xs text-slate-400">
            <span>Immutable Audit Ledger (AUDIT-01)</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span>Secrets &amp; Raw Payloads Withheld</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span className="font-mono text-slate-300">
              {allowCount} ALLOW / {denyCount} DENY
            </span>
          </div>
          <h2 className="text-lg font-semibold text-white mt-0.5">
            Audit Evidence Timeline (<code className="text-sm font-mono text-sky-300">GET /api/audit</code>)
          </h2>
        </div>

        {/* Interactive Filter Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
            <button
              type="button"
              onClick={() => onToggleScope(false)}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                !showAllTestsAudit ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Current Test ({selectedTestId || 'None'})
            </button>
            <button
              type="button"
              onClick={() => onToggleScope(true)}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                showAllTestsAudit ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All System Events
            </button>
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-md">
            <button
              type="button"
              onClick={() => setDecisionFilter('ALL')}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                decisionFilter === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({events.length})
            </button>
            <button
              type="button"
              onClick={() => setDecisionFilter('DENY')}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                decisionFilter === 'DENY' ? 'bg-rose-900/60 text-rose-200' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              DENY Only ({denyCount})
            </button>
            <button
              type="button"
              onClick={() => setDecisionFilter('ALLOW')}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                decisionFilter === 'ALLOW' ? 'bg-emerald-900/60 text-emerald-200' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              ALLOW Only ({allowCount})
            </button>
          </div>

          <input
            type="search"
            aria-label="Filter audit events by action, role, or reason code"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter action, role, or policy code..."
            className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-sky-500 w-56"
          />
        </div>
      </div>

      {filteredEvents.length === 0 ? (
        <div className="text-xs text-slate-500 py-8 text-center border border-dashed border-slate-800 rounded">
          No audit events match the active filter criteria.
        </div>
      ) : (
        <div className="overflow-x-auto border border-slate-800 rounded">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400">
                <th className="py-2.5 px-3 font-medium">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-medium">Decision</th>
                <th className="py-2.5 px-3 font-medium">Actor · Role</th>
                <th className="py-2.5 px-3 font-medium">Action</th>
                <th className="py-2.5 px-3 font-medium">Resource Reference (No Secrets)</th>
                <th className="py-2.5 px-3 font-medium">State Transition</th>
                <th className="py-2.5 px-3 font-medium text-right">Policy Code</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono">
              {filteredEvents.map((ev) => (
                <tr
                  key={ev.id}
                  className={
                    ev.decision === 'DENY'
                      ? 'bg-rose-950/20 hover:bg-rose-950/30'
                      : 'hover:bg-slate-800/30'
                  }
                >
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap tabular-nums">
                    {ev.timestamp.replace('T', ' ').slice(0, 19)}Z
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap font-semibold">
                    <span className={ev.decision === 'DENY' ? 'text-rose-400' : 'text-emerald-400'}>
                      {ev.decision}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-200 whitespace-nowrap">
                    {ev.role} · <span className="text-slate-400">{ev.actor}</span>
                  </td>
                  <td className="py-2.5 px-3 text-white whitespace-nowrap">{ev.action}</td>
                  <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={ev.resource}>
                    {ev.resource}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                    {ev.state_transition || '—'}
                  </td>
                  <td className="py-2.5 px-3 text-right whitespace-nowrap text-slate-400">
                    {ev.reason_code}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};
