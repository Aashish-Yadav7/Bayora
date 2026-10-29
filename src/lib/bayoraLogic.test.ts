import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getNextValidLifecycleState,
  isTransitionValidClientCheck,
  computeRoleCapabilities,
  formatDenialExplanation,
} from './bayoraLogic';

test('lifecycle state machine follows strict forward sequence Draft -> Ready -> Running -> Closed -> Results Released', () => {
  assert.equal(getNextValidLifecycleState('Draft'), 'Ready');
  assert.equal(getNextValidLifecycleState('Ready'), 'Running');
  assert.equal(getNextValidLifecycleState('Running'), 'Closed');
  assert.equal(getNextValidLifecycleState('Closed'), 'Results Released');
  assert.equal(getNextValidLifecycleState('Results Released'), null);

  assert.equal(isTransitionValidClientCheck('Draft', 'Results Released'), false);
  assert.equal(isTransitionValidClientCheck('Closed', 'Running'), false);
  assert.equal(isTransitionValidClientCheck('Running', 'Ready'), false);
  assert.equal(isTransitionValidClientCheck('Ready', 'Running'), true);
});

test('role capability matrix enforces Red, Blue, and Evaluator boundaries per state', () => {
  const redDraft = computeRoleCapabilities('RED_TEAM', 'Draft');
  assert.equal(redDraft.canSubmitRedPayload, true);
  assert.equal(redDraft.canSubmitBlueDefense, false);
  assert.equal(redDraft.canReleaseResults, false);

  const blueReady = computeRoleCapabilities('BLUE_TEAM', 'Ready');
  assert.equal(blueReady.canSubmitBlueDefense, true);
  assert.equal(blueReady.canSubmitRedPayload, false);
  assert.equal(blueReady.canStartRun, false);

  const redClosed = computeRoleCapabilities('RED_TEAM', 'Closed');
  assert.equal(redClosed.canSubmitRedPayload, false);
  assert.equal(redClosed.canReleaseResults, false);

  const evalClosed = computeRoleCapabilities('EVALUATOR', 'Closed');
  assert.equal(evalClosed.canReleaseResults, true);
});

test('formatDenialExplanation produces clear denial notice without exposing hidden artifacts', () => {
  const notice = formatDenialExplanation(
    403,
    {
      error: 'ACCESS_DENIED',
      code: 'SEC_01_RED_READ_BLUE_DEFENSE_DENIED',
      message: 'Cross-role isolation boundary violation: caller is not authorized to read Blue Team defense artifacts.',
    },
    'Read Unreleased Blue Defense'
  );

  assert.equal(notice.httpStatus, 403);
  assert.equal(notice.policyCode, 'SEC_01_RED_READ_BLUE_DEFENSE_DENIED');
  assert.equal(notice.secretLeakedInBody, false);
  assert.equal(notice.auditRecorded, true);
  assert.ok(notice.headline.includes('HTTP 403'));
});
