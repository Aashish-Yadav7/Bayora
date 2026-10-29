import React from 'react';
import {
  BayoraRole,
  LIFECYCLE_ORDER,
  LifecycleState,
  computeRoleCapabilities,
} from '../lib/bayoraLogic';
import { Play, Lock, CheckCircle2, ShieldAlert, ArrowRight } from 'lucide-react';

interface LifecycleStepperProps {
  currentState: LifecycleState;
  activeRole: BayoraRole;
  busyAction: string | null;
  onTransition: (action: 'ready' | 'start' | 'close' | 'release') => void;
  onAttemptInvalidTransition: () => void;
  onAttemptCrossRoleRead: (target: 'blue_defense' | 'red_payload') => void;
  onAttemptUnauthorizedRelease: () => void;
  onAttemptDirectNetworkCall: () => void;
}

export const LifecycleStepper: React.FC<LifecycleStepperProps> = ({
  currentState,
  activeRole,
  busyAction,
  onTransition,
  onAttemptInvalidTransition,
  onAttemptCrossRoleRead,
  onAttemptUnauthorizedRelease,
  onAttemptDirectNetworkCall,
}) => {
  const currentIdx = LIFECYCLE_ORDER.indexOf(currentState);
  const capabilities = computeRoleCapabilities(activeRole, currentState);

  return (
    <section
      aria-label="Test Lifecycle State Machine and Boundary Controls"
      className="border border-slate-800 bg-slate-900/60 p-5 rounded-lg space-y-5"
    >
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="text-xs text-slate-400">
            <span>Controlled Test Lifecycle State Machine</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span className="font-mono text-slate-300">Active Role: {activeRole}</span>
          </div>
          <h2 className="text-lg font-semibold text-white mt-0.5">
            State Progression &amp; Server-Enforced Transitions
          </h2>
        </div>

        {/* Authorized Lifecycle Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => onTransition('ready')}
            disabled={!capabilities.canStageReady || busyAction !== null}
            className={`px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
              capabilities.canStageReady
                ? 'bg-amber-600 hover:bg-amber-500 text-white cursor-pointer'
                : 'bg-slate-800/70 text-slate-500 cursor-not-allowed'
            }`}
          >
            <ArrowRight className="w-3.5 h-3.5" />
            <span>Stage Ready (Draft → Ready)</span>
          </button>

          <button
            type="button"
            onClick={() => onTransition('start')}
            disabled={!capabilities.canStartRun || busyAction !== null}
            className={`px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
              capabilities.canStartRun
                ? 'bg-sky-600 hover:bg-sky-500 text-white cursor-pointer'
                : 'bg-slate-800/70 text-slate-500 cursor-not-allowed'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            <span>Start Test Run (Ready → Running)</span>
          </button>

          <button
            type="button"
            onClick={() => onTransition('close')}
            disabled={!capabilities.canCloseTest || busyAction !== null}
            className={`px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
              capabilities.canCloseTest
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer'
                : 'bg-slate-800/70 text-slate-500 cursor-not-allowed'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Close Test (Running → Closed)</span>
          </button>

          <button
            type="button"
            onClick={() => onTransition('release')}
            disabled={!capabilities.canReleaseResults || busyAction !== null}
            className={`px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
              capabilities.canReleaseResults
                ? 'bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer'
                : 'bg-slate-800/70 text-slate-500 cursor-not-allowed'
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Release Results (Closed → Released)</span>
          </button>
        </div>
      </div>

      {/* 5-Stage Visual Stepper */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5">
        {LIFECYCLE_ORDER.map((stage, idx) => {
          const isCurrent = stage === currentState;
          const isCompleted = idx < currentIdx;
          return (
            <div
              key={stage}
              className={`px-3.5 py-2.5 rounded-md border text-left transition-colors ${
                isCurrent
                  ? 'border-sky-500/80 bg-sky-950/30 text-white'
                  : isCompleted
                  ? 'border-emerald-800/60 bg-emerald-950/15 text-emerald-200'
                  : 'border-slate-800 bg-slate-950/40 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span>0{idx + 1}</span>
                <span>{isCurrent ? 'CURRENT' : isCompleted ? 'PASSED' : 'LOCKED'}</span>
              </div>
              <div className="text-sm font-semibold mt-1 whitespace-nowrap truncate">
                {stage}
              </div>
            </div>
          );
        })}
      </div>

      {/* Interactive Adversarial Boundary Verification Bar (Demonstrates Fail-Closed Server Rejections) */}
      <div className="pt-2 border-t border-slate-800/80 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
        <div className="text-xs text-slate-400">
          <span className="font-semibold text-slate-200">Adversarial Boundary Probes (Live Backend Enforcement):</span>{' '}
          <span>Fire real unauthorized API calls to verify fail-closed 403/409 responses and secret-free DENY audit logs.</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onAttemptCrossRoleRead('blue_defense')}
            disabled={busyAction !== null}
            className="px-3 py-1.5 text-xs font-medium rounded border border-rose-800/70 bg-rose-950/30 text-rose-200 hover:bg-rose-900/40 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Probe SEC-01: Red Reads Blue Defense</span>
          </button>

          <button
            type="button"
            onClick={() => onAttemptCrossRoleRead('red_payload')}
            disabled={busyAction !== null}
            className="px-3 py-1.5 text-xs font-medium rounded border border-rose-800/70 bg-rose-950/30 text-rose-200 hover:bg-rose-900/40 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Probe SEC-02: Blue Reads Red Payload</span>
          </button>

          <button
            type="button"
            onClick={onAttemptUnauthorizedRelease}
            disabled={busyAction !== null}
            className="px-3 py-1.5 text-xs font-medium rounded border border-amber-800/70 bg-amber-950/30 text-amber-200 hover:bg-amber-900/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>Probe SEC-03: Non-Evaluator Release</span>
          </button>

          <button
            type="button"
            onClick={onAttemptInvalidTransition}
            disabled={busyAction !== null}
            className="px-3 py-1.5 text-xs font-medium rounded border border-amber-800/70 bg-amber-950/30 text-amber-200 hover:bg-amber-900/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>Probe STATE-01: Invalid State Jump</span>
          </button>

          <button
            type="button"
            onClick={onAttemptDirectNetworkCall}
            disabled={busyAction !== null}
            className="px-3 py-1.5 text-xs font-medium rounded border border-rose-800/70 bg-rose-950/30 text-rose-200 hover:bg-rose-900/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>Probe RUNTIME-01: Direct Red→Blue Net</span>
          </button>
        </div>
      </div>
    </section>
  );
};
