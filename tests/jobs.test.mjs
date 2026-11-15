import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizePayload, JobError, permanent } from '../packages/jobs/src/index.mjs';

test('job payloads are small allowlisted metadata, never content', () => {
  assert.deepEqual(sanitizePayload({ objectId: 'abc-1', attempt: 2, poison: true }), { objectId: 'abc-1', attempt: 2, poison: true });
  for (const bad of [{ text: 'a sentence with spaces' }, { nested: { a: 1 } }, { list: [1] }, { 'bad key': 1 }, { n: Infinity }, []]) assert.throws(() => sanitizePayload(bad), { code: 'JOB_PAYLOAD_INVALID' });
});

test('errors carry retryability explicitly', () => {
  assert.equal(new JobError('X').retryable, true);
  assert.equal(permanent('Y').retryable, false);
});
