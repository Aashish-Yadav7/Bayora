import test from 'node:test';
import assert from 'node:assert/strict';
import { buildTimeline } from './timeline.ts';
import type { AuditEvent, RedPayloadArtifact, TestResultsResponse } from '../types/bayora';

const ev = (o: Partial<AuditEvent>): AuditEvent => ({
  id: 'e', timestamp: '2026-01-01T10:00:00Z', test_id: 't', run_id: null, actor: 'x', role: 'RED_TEAM',
  action: 'READ', resource: 'r', decision: 'ALLOW', state_transition: null, reason_code: 'OK', ...o,
});
const payload: RedPayloadArtifact = {
  id: 'p1', test_id: 't', author_actor: 'red1', category: 'PROMPT_INJECTION', severity_tier: 'HIGH',
  payload_text: 'SECRET-ATTACK-TEXT', payload_sha256: 'a'.repeat(64), created_at: '2026-01-01T10:01:00Z',
};
const submit = ev({ id: 'e-sub', action: 'SUBMIT_RED_PAYLOAD', timestamp: '2026-01-01T10:01:00Z', actor: 'red1' });

test('red viewer sees own payload text once (no duplicate hidden bubble)', () => {
  const items = buildTimeline('RED_TEAM', [submit], [payload], [], null);
  const bubbles = items.filter((i) => i.kind === 'bubble');
  assert.equal(bubbles.length, 1);
  assert.ok(bubbles[0].kind === 'bubble' && bubbles[0].body === 'SECRET-ATTACK-TEXT' && bubbles[0].side === 'right');
});

test('blue and evaluator viewers only get a locked bubble, never the text', () => {
  for (const viewer of ['BLUE_TEAM', 'EVALUATOR'] as const) {
    const items = buildTimeline(viewer, [submit], [], [], null);
    const b = items.find((i) => i.kind === 'bubble');
    assert.ok(b && b.kind === 'bubble' && b.body === null && b.side === 'left' && b.team === 'red');
    assert.ok(!JSON.stringify(items).includes('SECRET-ATTACK-TEXT'));
  }
});

test('denials become red chips and transitions show an arrow', () => {
  const items = buildTimeline('RED_TEAM', [
    ev({ id: 'd', decision: 'DENY', action: 'CLOSE_TEST', reason_code: 'ROLE_NOT_ALLOWED', timestamp: '2026-01-01T10:02:00Z' }),
    ev({ id: 't', action: 'START_TEST', state_transition: 'Ready->Running', timestamp: '2026-01-01T10:03:00Z' }),
  ], [], [], null);
  assert.equal(items[0].kind === 'chip' && items[0].tone, 'deny');
  assert.ok(items[1].kind === 'chip' && items[1].text.includes('Ready → Running'));
});

test('items are ordered oldest to newest and results card comes last', () => {
  const results = { run_id: 'r1', approved_metrics: { resilience_score: 80 } } as unknown as TestResultsResponse;
  const items = buildTimeline('EVALUATOR', [
    ev({ id: 'b', action: 'CREATE_TEST', timestamp: '2026-01-01T09:00:00Z' }),
    ev({ id: 'a', action: 'CREATE_TEST', timestamp: '2026-01-01T08:00:00Z' }),
  ], [], [], results);
  assert.deepEqual(items.map((i) => i.id), ['a', 'b', 'res-r1']);
});

test('unreleased results (no metrics) add no result card', () => {
  const results = { run_id: 'r1', approved_metrics: null } as unknown as TestResultsResponse;
  assert.equal(buildTimeline('RED_TEAM', [], [], [], results).length, 0);
});
