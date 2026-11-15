import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startHarness, client } from './harness.mjs';
import { resolveSession } from '../../packages/identity/src/index.mjs';
import { withSession } from '../../packages/authorization/src/index.mjs';
import { requireConsent, CONSENT_POLICIES } from '../../packages/consent/src/index.mjs';
import { createLocalAdapter } from '../../packages/secure-intake/src/index.mjs';

test('consent API and enforcement on native PostgreSQL', async t => {
  const h = await startHarness('heard_test_consent');
  const secret = h.config.secrets.sessionSecret;
  const adapter = createLocalAdapter();
  const newContributor = async () => {
    const c = client(h.app);
    await c.request('POST', '/api/v1/anonymous/start', {});
    const session = await resolveSession(h.pool, c.cookie.split('=')[1], { secret });
    const caseId = randomUUID();
    await withSession(h.pool, session, x => adapter.createDraft(x, { caseId, subjectId: session.subjectId, kind: 'experience' }));
    return { c, session, caseId };
  };
  try {
    const owner = await newContributor();
    const path = `/api/v1/my/cases/${owner.caseId}/consents`;

    await t.test('public policy texts are versioned and digested', async () => {
      const res = await client(h.app).request('GET', '/api/v1/consent/policies');
      assert.equal(res.status, 200);
      assert.equal(res.body.policies.length, 6);
      assert.ok(res.body.policies.every(p => /^[a-f0-9]{64}$/.test(p.sha256)));
    });

    await t.test('initial state: nothing allowed', async () => {
      const res = await owner.c.request('GET', path);
      assert.equal(res.status, 200);
      assert.ok(Object.values(res.body.effective).every(e => e.status === 'not_granted'));
      assert.ok(res.body.preview.every(p => p.effective === false));
    });

    await t.test('grant requires the current version; scope is validated; preview reflects the result', async () => {
      const stale = await owner.c.request('POST', path, { purpose: 'private_processing', decision: 'grant', policyVersion: '2025-01-01.1' });
      assert.equal(stale.status, 409);
      const bad = await owner.c.request('POST', path, { purpose: 'helper_access', decision: 'grant', policyVersion: CONSENT_POLICIES.helper_access.version, scope: { recipients: ['all'] } });
      assert.equal(bad.status, 400);
      const ok = await owner.c.request('POST', path, { purpose: 'private_processing', decision: 'grant', policyVersion: CONSENT_POLICIES.private_processing.version });
      assert.equal(ok.status, 201);
      assert.equal(ok.body.effective.private_processing.status, 'granted');
      assert.equal(ok.body.effective.publication.status, 'not_granted', 'no inheritance');
      const pub = ok.body.preview.find(p => p.purpose === 'private_processing');
      assert.ok(pub.effective && pub.recipients.length > 0);
    });

    await t.test('withdrawal takes effect immediately and history is append-only', async () => {
      await owner.c.request('POST', path, { purpose: 'private_processing', decision: 'revoke' });
      await assert.rejects(withSession(h.pool, owner.session, c => requireConsent(c, owner.caseId, 'private_processing')), { code: 'CONSENT_REQUIRED' });
      const count = (await h.admin.query('SELECT count(*)::int AS n FROM heard_consent_records WHERE case_id=$1', [owner.caseId])).rows[0].n;
      assert.equal(count, 2);
      await assert.rejects(h.admin.query('UPDATE heard_consent_records SET decision=$1 WHERE case_id=$2', ['grant', owner.caseId]), /append-only/);
      await assert.rejects(h.admin.query('DELETE FROM heard_consent_records WHERE case_id=$1', [owner.caseId]), /append-only/);
    });

    await t.test('a policy text change makes earlier grants stale (no silent carry-over)', async () => {
      await owner.c.request('POST', path, { purpose: 'private_processing', decision: 'grant', policyVersion: CONSENT_POLICIES.private_processing.version });
      await h.admin.query("INSERT INTO heard_consent_records(case_id, actor_id, purpose, decision, policy_version, policy_text_sha256) VALUES($1,$2,'contact','grant',$3,$4)", [owner.caseId, owner.session.subjectId, CONSENT_POLICIES.contact.version, 'e'.repeat(64)]);
      const res = await owner.c.request('GET', path);
      assert.equal(res.body.effective.contact.status, 'stale');
      assert.match(res.body.preview.find(p => p.purpose === 'contact').summary, /previous policy/);
    });

    await t.test('other people cannot read or record consent on the case', async () => {
      const intruder = await newContributor();
      assert.equal((await intruder.c.request('GET', path)).status, 404);
      assert.equal((await intruder.c.request('POST', path, { purpose: 'publication', decision: 'grant', policyVersion: CONSENT_POLICIES.publication.version, scope: { assets: [randomUUID()], fields: ['summary'] } })).status, 404);
      await assert.rejects(withSession(h.pool, intruder.session, c => c.query("INSERT INTO heard_consent_records(case_id, actor_id, purpose, decision, policy_version, policy_text_sha256) VALUES($1,$2,'publication','grant','x',$3)", [owner.caseId, intruder.session.subjectId, 'a'.repeat(64)])), { code: '42501' });
      assert.equal((await withSession(h.pool, intruder.session, c => c.query('SELECT 1 FROM heard_consent_records WHERE case_id=$1', [owner.caseId]))).rows.length, 0);
      assert.equal((await client(h.app).request('GET', path)).status, 401);
      assert.equal((await owner.c.request('GET', '/api/v1/my/cases/not-a-uuid/consents')).status, 404);
    });

    await t.test('grants cannot be recorded without a policy text digest', async () => {
      await assert.rejects(h.admin.query("INSERT INTO heard_consent_records(case_id, actor_id, purpose, decision, policy_version) VALUES($1,$2,'contact','grant','v')", [owner.caseId, owner.session.subjectId]), { code: '23514' });
    });
  } finally {
    await h.stop();
  }
});
