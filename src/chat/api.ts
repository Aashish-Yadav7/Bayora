export type Role = 'RED_TEAM' | 'BLUE_TEAM' | 'EVALUATOR';

export const ROLES: Record<Role, { label: string; hint: string }> = {
  RED_TEAM: { label: 'Red Team', hint: 'Writes attack payloads' },
  BLUE_TEAM: { label: 'Blue Team', hint: 'Writes defense rules' },
  EVALUATOR: { label: 'Evaluator', hint: 'Runs the test and releases results' },
};

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Session is an HttpOnly cookie set by the gateway; role headers only matter in demo mode. */
function buildHeaders(role: Role): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'X-Requested-With': 'bayora',
    'X-Bayora-Role': role,
    'X-Bayora-Actor': `${role.toLowerCase()}-ui`,
  };
}

export async function api<T>(path: string, role: Role, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? 'GET',
    headers: buildHeaders(role),
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = typeof data.message === 'string' ? data.message : `Request failed (${res.status})`;
    throw new ApiError(res.status, String(data.code ?? data.error ?? 'ERROR'), message);
  }
  return data as T;
}

export const STATES = ['Draft', 'Ready', 'Running', 'Closed', 'Results Released'] as const;

export function nextAction(state: string): { path: string; label: string } | null {
  switch (state) {
    case 'Draft': return { path: 'ready', label: 'Mark ready' };
    case 'Ready': return { path: 'start', label: 'Start evaluation' };
    case 'Running': return { path: 'close', label: 'Close test' };
    case 'Closed': return { path: 'results/release', label: 'Release results' };
    default: return null;
  }
}

export function timeLabel(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const now = new Date();
  return d.toDateString() === now.toDateString()
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { day: 'numeric', month: 'short' });
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map((p) => p.charAt(0).toUpperCase()).join('') || '?';
}
