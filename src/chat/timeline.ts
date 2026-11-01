import type { AuditEvent, BlueDefenseArtifact, RedPayloadArtifact, TestResultsResponse } from '../types/bayora';
import type { Role } from './api';

export type TimelineItem =
  | { kind: 'chip'; id: string; time: string; text: string; tone: 'info' | 'deny' | 'ok' }
  | {
      kind: 'bubble'; id: string; time: string; side: 'left' | 'right'; team: 'red' | 'blue';
      author: string; title: string; body: string | null; footer: string;
    }
  | { kind: 'result'; id: string; time: string; results: TestResultsResponse };

const pretty = (s: string) => s.replace(/_/g, ' ').toLowerCase();

/** Builds a chat-style timeline. Hidden artifacts (other team's content) become locked bubbles. */
export function buildTimeline(
  viewer: Role,
  events: AuditEvent[],
  payloads: RedPayloadArtifact[],
  defenses: BlueDefenseArtifact[],
  results: TestResultsResponse | null,
): TimelineItem[] {
  const items: TimelineItem[] = [];

  for (const p of payloads) {
    items.push({
      kind: 'bubble', id: p.id, time: p.created_at, side: 'right', team: 'red', author: p.author_actor,
      title: `${p.category.replace(/_/g, ' ')} · ${p.severity_tier}`, body: p.payload_text,
      footer: `SHA-256 ${p.payload_sha256.slice(0, 10)}…`,
    });
  }
  for (const d of defenses) {
    items.push({
      kind: 'bubble', id: d.id, time: d.created_at, side: 'right', team: 'blue', author: d.author_actor,
      title: `${d.defense_name} · ${d.rule_type.replace(/_/g, ' ')}`, body: d.defense_config_secret,
      footer: `SHA-256 ${d.config_sha256.slice(0, 10)}…`,
    });
  }

  for (const e of events) {
    const own = (e.action === 'SUBMIT_RED_PAYLOAD' && viewer === 'RED_TEAM') || (e.action === 'SUBMIT_BLUE_DEFENSE' && viewer === 'BLUE_TEAM');
    if (e.decision === 'ALLOW' && (e.action === 'SUBMIT_RED_PAYLOAD' || e.action === 'SUBMIT_BLUE_DEFENSE')) {
      if (own) continue; // the real bubble is already shown
      const red = e.action === 'SUBMIT_RED_PAYLOAD';
      items.push({
        kind: 'bubble', id: e.id, time: e.timestamp, side: 'left', team: red ? 'red' : 'blue', author: e.actor,
        title: red ? 'Red Team payload' : 'Blue Team defense', body: null, footer: 'Hidden by isolation policy',
      });
    } else if (e.decision === 'DENY') {
      items.push({ kind: 'chip', id: e.id, time: e.timestamp, tone: 'deny', text: `Blocked: ${pretty(e.action)} (${pretty(e.reason_code)})` });
    } else if (e.state_transition) {
      items.push({ kind: 'chip', id: e.id, time: e.timestamp, tone: 'ok', text: `${e.state_transition.replace('->', ' → ')} · ${e.actor}` });
    } else if (e.action.includes('CREATE')) {
      items.push({ kind: 'chip', id: e.id, time: e.timestamp, tone: 'info', text: `Test created by ${e.actor}` });
    }
  }

  if (results && results.approved_metrics) {
    items.push({ kind: 'result', id: `res-${results.run_id ?? 'x'}`, time: new Date(8.64e15).toISOString(), results });
  }

  return items.sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
}
