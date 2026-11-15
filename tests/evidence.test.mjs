import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeDetail, actorKind, OPERATIONS, SOURCES, MANIFEST_NOTICE } from '../packages/evidence/src/index.mjs';

test('ledger detail accepts only short allowlisted values (no narrative or identity can enter digests)', () => {
  assert.deepEqual(sanitizeDetail({ source: 'self_recorded', captured: '2026-03' }), { source: 'self_recorded', captured: '2026-03' });
  for (const bad of [{ note: 'free text' }, { source: 'my neighbour Ana' }, { captured: 'last spring' }, { reason: 'Has Spaces' }, { engine: 'x'.repeat(81) }, { reason: 7 }]) {
    assert.throws(() => sanitizeDetail(bad), { code: 'EVIDENCE_DETAIL_INVALID' });
  }
  assert.throws(() => sanitizeDetail([]), { code: 'EVIDENCE_DETAIL_INVALID' });
});

test('actor kinds and vocabulary make no authenticity claims', () => {
  assert.equal(actorKind({ subjectId: 'a', assurance: 'anonymous_recovery' }, 'a'), 'contributor');
  assert.equal(actorKind({ subjectId: 'b', assurance: 'staff_mfa' }, 'a'), 'staff');
  assert.equal(actorKind({ subjectId: 'c', assurance: 'anonymous_recovery' }, 'a'), 'helper');
  assert.ok(!OPERATIONS.some(o => /authentic|true|confirmed/.test(o)));
  assert.ok(!SOURCES.some(s => /verified/.test(s)));
  assert.match(MANIFEST_NOTICE, /does not establish/);
});
