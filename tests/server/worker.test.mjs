import test from 'node:test';
import assert from 'node:assert/strict';
import { startHarness, client } from './harness.mjs';
import { runOnce } from '../../scripts/worker.mjs';
import { createFakeScanner } from '../../packages/quarantine/src/index.mjs';
import { silent } from './harness.mjs';

test('worker pass purges expired drafts and runs scans under the job role', async () => {
  const h = await startHarness('heard_test_worker', { HEARD_OBJECT_STORAGE_DRIVER: 'memory' });
  try {
    const c = client(h.app);
    await c.request('POST', '/api/v1/anonymous/start', {});
    const caseId = (await c.request('POST', '/api/v1/drafts', { kind: 'question' })).body.caseId;
    await h.admin.query("UPDATE heard_intake_drafts SET expires_at=now()-interval '1 second' WHERE case_id=$1", [caseId]);
    const result = await runOnce({ pool: h.pool, storage: h.app.context.storage, scanner: createFakeScanner(), workerId: '00000000-0000-4000-8000-00000000beef', logger: silent });
    assert.deepEqual({ drafts: result.drafts, uploads: result.uploads, scans: result.scans.length }, { drafts: 1, uploads: 0, scans: 0 });
  } finally { await h.stop(); }
});
