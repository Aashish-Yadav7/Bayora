/**
 * Pure domain logic for Bayora Systems frontend state representation,
 * lifecycle transition validation, role capability matrix, and zero-leakage
 * denial explanation formatting.
 * Note: All actual security enforcement occurs server-side in Python (`backend/app/`).
 */

export type BayoraRole = 'RED_TEAM' | 'BLUE_TEAM' | 'EVALUATOR';

export type LifecycleState = 'Draft' | 'Ready' | 'Running' | 'Closed' | 'Results Released';

export const LIFECYCLE_ORDER: LifecycleState[] = [
  'Draft',
  'Ready',
  'Running',
  'Closed',
  'Results Released',
];

export interface RoleDescriptor {
  role: BayoraRole;
  label: string;
  defaultActor: string;
  networkPlane: string;
  summary: string;
}

export const ROLE_DESCRIPTORS: Record<BayoraRole, RoleDescriptor> = {
  RED_TEAM: {
    role: 'RED_TEAM',
    label: 'Red Team Operator',
    defaultActor: 'marcus.vance@red.bayora',
    networkPlane: 'red-net (isolated internal bridge)',
    summary: 'Creates and submits private adversarial payloads; triggers authorized test runs.',
  },
  BLUE_TEAM: {
    role: 'BLUE_TEAM',
    label: 'Blue Team Defender',
    defaultActor: 'sara.chen@blue.bayora',
    networkPlane: 'blue-net (isolated internal bridge)',
    summary: 'Configures private defensive guard rules; isolated from Red payloads.',
  },
  EVALUATOR: {
    role: 'EVALUATOR',
    label: 'Lead Safety Evaluator',
    defaultActor: 'elena.rostova@bayora.sys',
    networkPlane: 'control-net (mediating control plane)',
    summary: 'Orchestrates test lifecycle, closes completed runs, and releases approved results.',
  },
};

export function getNextValidLifecycleState(current: LifecycleState): LifecycleState | null {
  switch (current) {
    case 'Draft':
      return 'Ready';
    case 'Ready':
      return 'Running';
    case 'Running':
      return 'Closed';
    case 'Closed':
      return 'Results Released';
    case 'Results Released':
      return null;
    default:
      return null;
  }
}

export function isTransitionValidClientCheck(from: LifecycleState, to: LifecycleState): boolean {
  return getNextValidLifecycleState(from) === to;
}

export interface AvailableRoleActions {
  canCreateTest: boolean;
  canSubmitRedPayload: boolean;
  canReadOwnRedPayloads: boolean;
  canSubmitBlueDefense: boolean;
  canReadOwnBlueDefenses: boolean;
  canStageReady: boolean;
  canStartRun: boolean;
  canCloseTest: boolean;
  canReleaseResults: boolean;
}

export function computeRoleCapabilities(role: BayoraRole, state: LifecycleState): AvailableRoleActions {
  const isEditableState = state === 'Draft' || state === 'Ready';
  return {
    canCreateTest: role === 'EVALUATOR' || role === 'RED_TEAM',
    canSubmitRedPayload: role === 'RED_TEAM' && isEditableState,
    canReadOwnRedPayloads: role === 'RED_TEAM',
    canSubmitBlueDefense: role === 'BLUE_TEAM' && isEditableState,
    canReadOwnBlueDefenses: role === 'BLUE_TEAM',
    canStageReady: state === 'Draft',
    canStartRun: (role === 'RED_TEAM' || role === 'EVALUATOR') && state === 'Ready',
    canCloseTest: role === 'EVALUATOR' && state === 'Running',
    canReleaseResults: role === 'EVALUATOR' && state === 'Closed',
  };
}

export interface SanitizedDenialNotice {
  httpStatus: number;
  policyCode: string;
  headline: string;
  explanation: string;
  auditRecorded: boolean;
  secretLeakedInBody: false;
}

export function formatDenialExplanation(
  httpStatus: number,
  responseBody: Record<string, unknown>,
  attemptedActionLabel: string
): SanitizedDenialNotice {
  const code = typeof responseBody.code === 'string' ? responseBody.code : 'POLICY_DENIED';
  const message =
    typeof responseBody.message === 'string'
      ? responseBody.message
      : typeof responseBody.detail === 'string'
      ? responseBody.detail
      : 'Request rejected by Bayora server-side policy engine.';

  return {
    httpStatus,
    policyCode: code,
    headline: `Blocked: ${attemptedActionLabel} (HTTP ${httpStatus})`,
    explanation: `${message} Protected artifacts were withheld from the error response and an immutable DENY audit event was recorded.`,
    auditRecorded: true,
    secretLeakedInBody: false,
  };
}
