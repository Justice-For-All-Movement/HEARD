import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startHarness, client } from './harness.mjs';
import { CONSENT_POLICIES } from '../../packages/consent/src/index.mjs';
import { purgeExpiredDrafts, MAX_OPEN_DRAFTS } from '../../packages/drafts/src/index.mjs';
import { resolveSession, provisionStaff, startStaffSession } from '../../packages/identity/src/index.mjs';
import { assignStaff } from '../../packages/authorization/src/index.mjs';

const narrative = 'A fictional account written only for automated testing purposes.';
const consent = { purpose: 'private_processing', decision: 'grant', policyVersion: CONSENT_POLICIES.private_processing.version };

test('drafts, consent-gated idempotent submission and receipts on native PostgreSQL', async t => {
  const h = await startHarness('heard_test_drafts');
  const secret = h.config.secrets.sessionSecret;
  const contributor = async () => {
    const c = client(h.app);
    const start = await c.request('POST', '/api/v1/anonymous/start', {});
    const draft = await c.request('POST', '/api/v1/drafts', { kind: 'experience' });
    assert.equal(draft.status, 201);
    return { c, code: start.body.recoveryCode, caseId: draft.body.caseId };
  };
  try {
    const { c, code, caseId } = await contributor();
    const base = `/api/v1/drafts/${caseId}`;

    await t.test('schema endpoint and draft creation', async () => {
      const schema = await c.request('GET', '/api/v1/intake/schema');
      assert.equal(schema.status, 200);
      assert.equal(schema.body.steps.length, 7);
      const got = await c.request('GET', base);
      assert.deepEqual({ revision: got.body.revision, kind: got.body.kind, status: got.body.status, answers: got.body.answers }, { revision: 0, kind: 'experience', status: 'draft', answers: { kind: 'experience' } });
      assert.equal((await c.request('POST', '/api/v1/drafts', { kind: 'gossip' })).status, 400);
      assert.equal((await client(h.app).request('POST', '/api/v1/drafts', { kind: 'question' })).status, 401);
    });

    await t.test('autosave uses revisions; stale saves never overwrite', async () => {
      const first = await c.request('PUT', base, { revision: 0, answers: { identity_mode: 'private', narrative } });
      assert.equal(first.status, 200); assert.equal(first.body.revision, 1);
      const stale = await c.request('PUT', base, { revision: 0, answers: { narrative: 'overwrite attempt from an old tab' } });
      assert.equal(stale.status, 409);
      assert.equal((await c.request('GET', base)).body.answers.narrative, narrative);
      const invalid = await c.request('PUT', base, { revision: 1, answers: { email: 'x@example.org' } });
      assert.equal(invalid.status, 400); assert.equal(invalid.body.error.fields.email, 'unknown_field');
      assert.equal((await c.request('PUT', base, { revision: 1, answers: { kind: 'question' } })).status, 400, 'kind is fixed at creation');
    });

    await t.test('answers are encrypted at rest', async () => {
      const row = (await h.admin.query('SELECT ciphertext FROM heard_intake_drafts WHERE case_id=$1', [caseId])).rows[0];
      assert.doesNotMatch(row.ciphertext, /fictional|automated/);
      const dump = JSON.stringify((await h.admin.query('SELECT * FROM heard_case_events')).rows) + JSON.stringify((await h.admin.query('SELECT * FROM heard_audit_events')).rows);
      assert.doesNotMatch(dump, /fictional account/);
    });

    await t.test('submission requires current processing consent and complete answers', async () => {
      const noConsent = await c.request('POST', `${base}/submit`, { revision: 1 }, { 'idempotency-key': randomUUID() });
      assert.equal(noConsent.status, 409); assert.equal(noConsent.body.error.code, 'CONSENT_REQUIRED');
      assert.equal((await c.request('POST', `/api/v1/my/cases/${caseId}/consents`, consent)).status, 201);
      assert.equal((await c.request('POST', `${base}/submit`, { revision: 0 }, { 'idempotency-key': randomUUID() })).status, 409, 'must submit the reviewed revision');
      assert.equal((await c.request('POST', `${base}/submit`, { revision: 1 })).status, 400, 'idempotency key required');
      const second = await contributor();
      await second.c.request('POST', `/api/v1/my/cases/${second.caseId}/consents`, consent);
      const incomplete = await second.c.request('POST', `/api/v1/drafts/${second.caseId}/submit`, { revision: 0 }, { 'idempotency-key': randomUUID() });
      assert.equal(incomplete.status, 400);
      assert.equal(incomplete.body.error.fields.narrative, 'required');
    });

    let reference;
    await t.test('submit is exactly-once: retries return the same receipt, other attempts are refused', async () => {
      const key = randomUUID();
      const results = await Promise.all([1, 2, 3].map(() => c.request('POST', `${base}/submit`, { revision: 1 }, { 'idempotency-key': key })));
      assert.ok(results.every(r => r.status === 201 || r.status === 200), JSON.stringify(results.map(r => r.status)));
      assert.equal(results.filter(r => r.status === 201).length, 1);
      reference = results[0].body.reference;
      assert.ok(results.every(r => r.body.reference === reference));
      assert.match(reference, /^HRD-R-/);
      assert.doesNotMatch(JSON.stringify(results[0].body), /fictional/);
      const different = await c.request('POST', `${base}/submit`, { revision: 1 }, { 'idempotency-key': randomUUID() });
      assert.equal(different.status, 409);
      assert.equal((await c.request('PUT', base, { revision: 1, answers: { narrative: 'edit after submission attempt' } })).status, 409);
      assert.equal((await h.admin.query("SELECT count(*)::int AS n FROM heard_case_events WHERE case_id=$1 AND event_type='case_submitted'", [caseId])).rows[0].n, 1);
    });

    await t.test('status pages show state and reference only; the receipt grants nothing by itself', async () => {
      const mine = await c.request('GET', '/api/v1/my/cases');
      assert.deepEqual(mine.body.cases.map(x => [x.caseId, x.status, x.reference]), [[caseId, 'submitted', reference]]);
      const one = await c.request('GET', `/api/v1/my/cases/${caseId}`);
      assert.deepEqual(Object.keys(one.body).sort(), ['caseId', 'kind', 'receipt', 'status', 'updatedAt']);
      assert.equal((await client(h.app).request('GET', `/api/v1/my/cases/${caseId}`)).status, 401);
      const other = await contributor();
      assert.equal((await other.c.request('GET', base)).status, 404);
      assert.equal((await other.c.request('GET', `/api/v1/my/cases/${caseId}`)).status, 404);
      assert.equal((await other.c.request('PUT', base, { revision: 1, answers: {} })).status, 404);
    });

    await t.test('anonymous resume: the recovery code reopens only its own drafts', async () => {
      const fresh = client(h.app);
      const redeemed = await fresh.request('POST', '/api/v1/anonymous/redeem', { recoveryCode: code });
      assert.equal(redeemed.status, 200);
      assert.equal((await fresh.request('GET', base)).body.receipt.reference, reference);
    });

    await t.test('assigned MFA staff can read submitted answers; unassigned staff cannot', async () => {
      const staffId = await provisionStaff(h.pool, { role: 'reviewer', purpose: 'synthetic review', expiresAt: new Date(Date.now() + 86_400_000) });
      const staff = client(h.app); staff.cookie = `__Host-heard_session=${(await startStaffSession(h.pool, staffId, { secret, mfaVerified: true })).token}`;
      assert.equal((await staff.request('GET', base)).status, 404);
      await assignStaff(h.pool, { caseId, staffSubjectId: staffId, role: 'reviewer', purpose: 'synthetic review', expiresAt: new Date(Date.now() + 3_600_000) });
      const seen = await staff.request('GET', base);
      assert.equal(seen.status, 200);
      assert.equal(seen.body.answers.narrative, narrative);
      assert.equal((await staff.request('PUT', base, { revision: 1, answers: {} })).status, 404, 'staff cannot edit contributor answers');
    });

    await t.test('withdrawing a draft deletes its encrypted answers', async () => {
      const w = await contributor();
      const res = await w.c.request('DELETE', `/api/v1/drafts/${w.caseId}`);
      assert.equal(res.status, 200); assert.equal(res.body.answersDeleted, true);
      assert.equal((await h.admin.query('SELECT count(*)::int AS n FROM heard_intake_drafts WHERE case_id=$1', [w.caseId])).rows[0].n, 0);
      assert.equal((await h.admin.query('SELECT status FROM heard_cases WHERE id=$1', [w.caseId])).rows[0].status, 'withdrawn');
    });

    await t.test('expired drafts are purged by the job role; submitted and live drafts are untouched', async () => {
      const e = await contributor();
      const live = await contributor();
      await h.admin.query("UPDATE heard_intake_drafts SET expires_at=now()-interval '1 minute' WHERE case_id=$1", [e.caseId]);
      assert.equal(await purgeExpiredDrafts(h.pool), 1);
      assert.equal((await h.admin.query('SELECT status FROM heard_cases WHERE id=$1', [e.caseId])).rows[0].status, 'withdrawn');
      assert.equal((await h.admin.query('SELECT status FROM heard_cases WHERE id=$1', [live.caseId])).rows[0].status, 'draft');
      assert.equal((await h.admin.query('SELECT count(*)::int AS n FROM heard_intake_drafts WHERE case_id=$1', [caseId])).rows[0].n, 1);
      assert.equal(await purgeExpiredDrafts(h.pool), 0);
    });

    await t.test('open drafts per principal are capped', async () => {
      const capped = client(h.app);
      await capped.request('POST', '/api/v1/anonymous/start', {});
      for (let i = 0; i < MAX_OPEN_DRAFTS; i++) assert.equal((await capped.request('POST', '/api/v1/drafts', { kind: 'question' })).status, 201);
      assert.equal((await capped.request('POST', '/api/v1/drafts', { kind: 'question' })).status, 429);
    });

    await t.test('drafts never appear in public routes', async () => {
      for (const path of ['/api/v1/archive', '/api/v1/drafts', `/api/v1/public/${caseId}`]) {
        const res = await client(h.app, { origin: null }).request('GET', path);
        assert.ok([404, 405].includes(res.status), path);
      }
    });
  } finally {
    await h.stop();
  }
});
