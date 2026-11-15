import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startHarness, client } from './harness.mjs';
import { enqueue, runJobs, JobError, permanent, MAX_ACTIVE_JOBS_PER_CASE, sanitizePayload } from '../../packages/jobs/src/index.mjs';
import { withScope } from '../../packages/database/src/index.mjs';

test('durable job framework on native PostgreSQL', async t => {
  const h = await startHarness('heard_test_jobs');
  const c = client(h.app);
  await c.request('POST', '/api/v1/anonymous/start', {});
  const caseId = (await c.request('POST', '/api/v1/drafts', { kind: 'question' })).body.caseId;
  const add = (kind, extra = {}) => enqueue(h.admin, { kind, caseId, dedupeKey: `${kind}:${randomUUID()}`, ...extra });
  const job = async id => (await h.admin.query('SELECT state, attempts, last_error_code FROM heard_jobs WHERE id=$1', [id])).rows[0];
  const ready = () => h.admin.query("UPDATE heard_jobs SET available_at=now() WHERE state='queued'");
  try {
    await t.test('deduplicated enqueue never creates a second job', async () => {
      const a = await enqueue(h.admin, { kind: 'demo_echo', caseId, dedupeKey: 'demo:once' });
      const b = await enqueue(h.admin, { kind: 'demo_echo', caseId, dedupeKey: 'demo:once' });
      assert.equal(a.created, true); assert.equal(b.created, false); assert.equal(a.jobId, b.jobId);
      assert.throws(() => sanitizePayload({ narrative: 'free text with spaces' }), { code: 'JOB_PAYLOAD_INVALID' });
      await assert.rejects(enqueue(h.admin, { kind: 'Bad Kind', caseId, dedupeKey: 'x' }), { code: 'JOB_KIND_INVALID' });
    });

    await t.test('success commits side effects exactly once, even with concurrent workers', async () => {
      await h.admin.query('CREATE TABLE IF NOT EXISTS demo_effects(job_id uuid PRIMARY KEY); GRANT INSERT ON demo_effects TO heard_job_worker');
      for (let i = 0; i < 6; i++) await add('demo_effect');
      const handler = async jobRow => ({ commit: async cl => { await cl.query('INSERT INTO demo_effects(job_id) VALUES($1)', [jobRow.id]); } });
      const [a, b, c2] = await Promise.all([1, 2, 3].map(() => runJobs(h.pool, { kind: 'demo_effect', handler, limit: 6 })));
      assert.equal([...a, ...b, ...c2].filter(r => r.outcome === 'succeeded').length, 6);
      assert.equal((await h.admin.query('SELECT count(*)::int AS n FROM demo_effects')).rows[0].n, 6);
    });

    await t.test('retryable failures back off; poison jobs dead-letter without blocking others', async () => {
      const poison = await add('demo_mixed', { maxAttempts: 3, payload: { poison: true } });
      const good = await add('demo_mixed');
      const handler = async j => { if (j.payload.poison) throw new JobError('DEMO_PARSER_FAULT'); return {}; };
      const first = await runJobs(h.pool, { kind: 'demo_mixed', handler, backoffMs: [60_000] });
      assert.deepEqual(first.map(r => r.outcome).sort(), ['retry', 'succeeded']);
      assert.deepEqual(await runJobs(h.pool, { kind: 'demo_mixed', handler }), [], 'backoff holds the retry');
      for (let i = 0; i < 2; i++) { await ready(); await runJobs(h.pool, { kind: 'demo_mixed', handler, backoffMs: [0] }); }
      assert.deepEqual(await job(poison.jobId), { state: 'failed', attempts: 3, last_error_code: 'DEMO_PARSER_FAULT' });
      assert.equal((await job(good.jobId)).state, 'succeeded');
      const perm = await add('demo_perm');
      await runJobs(h.pool, { kind: 'demo_perm', handler: async () => { throw permanent('DEMO_UNSUPPORTED'); } });
      assert.deepEqual(await job(perm.jobId), { state: 'failed', attempts: 1, last_error_code: 'DEMO_UNSUPPORTED' });
      await add('demo_crash');
      const crashed = await runJobs(h.pool, { kind: 'demo_crash', handler: async () => { throw new Error('secret stack detail'); } });
      assert.equal(crashed[0].code, 'JOB_HANDLER_ERROR', 'raw error messages never become error codes');
    });

    await t.test('runs exceeding their budget are aborted and retried', async () => {
      const slow = await add('demo_slow');
      let aborted = false;
      const res = await runJobs(h.pool, { kind: 'demo_slow', timeoutMs: 50, handler: (_j, { signal }) => new Promise(r => { signal.addEventListener('abort', () => { aborted = true; }); setTimeout(r, 1000); }) });
      assert.equal(res[0].code, 'JOB_TIMEOUT'); assert.equal(aborted, true);
      assert.equal((await job(slow.jobId)).state, 'queued');
    });

    await t.test('a killed worker’s lease expires and another worker resumes; the late worker applies nothing', async () => {
      const k = await add('demo_kill');
      await h.admin.query("UPDATE heard_jobs SET state='leased', lease_owner=$2, lease_until=now()-interval '1 second', attempts=1 WHERE id=$1", [k.jobId, randomUUID()]);
      const resumed = await runJobs(h.pool, { kind: 'demo_kill', handler: async () => ({}) });
      assert.equal(resumed[0].outcome, 'succeeded');
      assert.equal((await job(k.jobId)).attempts, 2);
      const late = await add('demo_late');
      let release;
      const gate = new Promise(r => { release = r; });
      const slowRun = runJobs(h.pool, { kind: 'demo_late', handler: async () => { await gate; return { commit: async () => { throw new Error('must not commit'); } }; } });
      await new Promise(r => setTimeout(r, 150));
      await h.admin.query("UPDATE heard_jobs SET lease_until=now()-interval '1 second' WHERE id=$1", [late.jobId]);
      const other = await runJobs(h.pool, { kind: 'demo_late', handler: async () => ({}) });
      assert.equal(other[0].outcome, 'succeeded');
      release();
      assert.equal((await slowRun)[0].outcome, 'lease_lost');
      assert.equal((await job(late.jobId)).state, 'succeeded');
    });

    await t.test('contributors see and cancel jobs on their own case only; cancelled jobs never commit', async () => {
      const cancelMe = await add('demo_cancel');
      const list = await c.request('GET', `/api/v1/my/cases/${caseId}/jobs`);
      assert.equal(list.status, 200);
      assert.ok(list.body.jobs.some(j => j.jobId === cancelMe.jobId && j.state === 'queued'));
      assert.ok(list.body.jobs.every(j => !('payload' in j) && !('leaseOwner' in j)));
      const intruder = client(h.app); await intruder.request('POST', '/api/v1/anonymous/start', {});
      assert.equal((await intruder.request('GET', `/api/v1/my/cases/${caseId}/jobs`)).status, 404);
      assert.equal((await intruder.request('POST', `/api/v1/jobs/${cancelMe.jobId}/cancel`, {})).status, 404);
      let release;
      const gate = new Promise(r => { release = r; });
      let committed = false;
      const run = runJobs(h.pool, { kind: 'demo_cancel', handler: async () => { await gate; return { commit: async () => { committed = true; } }; } });
      await new Promise(r => setTimeout(r, 150));
      assert.equal((await c.request('POST', `/api/v1/jobs/${cancelMe.jobId}/cancel`, {})).status, 200, 'cancel while leased');
      release();
      assert.equal((await run)[0].outcome, 'lease_lost');
      assert.equal(committed, false);
      assert.equal((await job(cancelMe.jobId)).state, 'cancelled');
      assert.equal((await c.request('POST', `/api/v1/jobs/${cancelMe.jobId}/cancel`, {})).status, 404, 'finished jobs cannot be cancelled again');
    });

    await t.test('workers are confined to their declared kind; per-case active jobs are bounded', async () => {
      await add('demo_other');
      const seen = await withScope(h.pool, { role: 'heard_job_worker', settings: { job_purpose: 'demo_echo' } }, x => x.query('SELECT DISTINCT kind FROM heard_jobs'));
      assert.deepEqual(seen.rows.map(r => r.kind), ['demo_echo']);
      const active = (await h.admin.query("SELECT count(*)::int AS n FROM heard_jobs WHERE case_id=$1 AND state IN ('queued','leased')", [caseId])).rows[0].n;
      for (let i = active; i < MAX_ACTIVE_JOBS_PER_CASE; i++) await add('demo_fill');
      await assert.rejects(add('demo_fill'), { code: 'JOB_QUOTA_REACHED' });
    });
  } finally {
    await h.stop();
  }
});
