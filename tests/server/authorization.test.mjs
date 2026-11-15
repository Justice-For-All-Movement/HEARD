import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startHarness } from './harness.mjs';
import { startAnonymous, resolveSession, provisionStaff, startStaffSession } from '../../packages/identity/src/index.mjs';
import { withSession, authorizeCase, authorizeObject, createGrant, revokeGrant, assignStaff } from '../../packages/authorization/src/index.mjs';
import { createLocalAdapter } from '../../packages/secure-intake/src/index.mjs';

const adapter = createLocalAdapter();
const hour = () => new Date(Date.now() + 3_600_000);

test('adversarial authorization matrix on native PostgreSQL (application policy + RLS)', async t => {
  const h = await startHarness('heard_test_authz');
  const secret = h.config.secrets.sessionSecret;
  const session = async () => resolveSession(h.pool, (await startAnonymous(h.pool, { secret })).token, { secret });
  const staff = async role => {
    const id = await provisionStaff(h.pool, { role, purpose: 'synthetic matrix', expiresAt: new Date(Date.now() + 86_400_000) });
    return resolveSession(h.pool, (await startStaffSession(h.pool, id, { secret, mfaVerified: true })).token, { secret });
  };
  const ok = (s, fn) => withSession(h.pool, s, fn);
  const denied = (promise, message) => assert.rejects(promise, { code: 'NOT_FOUND' }, message);
  try {
    const A = await session(); const B = await session(); const H = await session();
    const R = await staff('reviewer'); const R2 = await staff('reviewer'); const ADM = await staff('administrator');
    const CA = randomUUID(); const CB = randomUUID(); const OA = randomUUID(); const OA2 = randomUUID();
    await ok(A, async c => {
      await adapter.createDraft(c, { caseId: CA, subjectId: A.subjectId, kind: 'experience' });
      await c.query("INSERT INTO heard_private_objects(id, case_id, storage_ref, checksum_sha256) VALUES($1,$2,'synthetic://a/1',repeat('a',64)),($3,$2,'synthetic://a/2',repeat('b',64))", [OA, CA, OA2]);
      await adapter.submit(c, { caseId: CA, actorId: A.subjectId, policyVersion: 'v1' });
    });
    await ok(B, c => adapter.createDraft(c, { caseId: CB, subjectId: B.subjectId, kind: 'question' }));

    await t.test('horizontal: other contributors cannot read, guess or enumerate cases and objects', async () => {
      await ok(A, c => authorizeCase(c, A, 'case.read', CA));
      await denied(ok(B, c => authorizeCase(c, B, 'case.read', CA)));
      await denied(ok(B, c => authorizeCase(c, B, 'case.read', randomUUID())), 'nonexistent looks identical');
      await denied(ok(B, c => authorizeObject(c, B, 'evidence.read', OA)));
      const visible = await ok(B, c => c.query('SELECT id FROM heard_cases UNION ALL SELECT id FROM heard_private_objects UNION ALL SELECT case_id FROM heard_case_events'));
      assert.ok(visible.rows.every(r => r.id === CB), 'B sees only its own records');
      const updated = await ok(B, c => c.query("UPDATE heard_cases SET status='withdrawn' WHERE id=$1", [CA]));
      assert.equal(updated.rowCount, 0, 'blind update of another case affects nothing');
    });

    await t.test('owners cannot skip review or rewrite immutable fields, even via direct SQL', async () => {
      await assert.rejects(ok(A, c => c.query("UPDATE heard_cases SET status='review' WHERE id=$1", [CA])), { code: '42501' });
      await assert.rejects(ok(B, c => c.query("UPDATE heard_cases SET status='closed' WHERE id=$1", [CB])), /Invalid case transition|row-level security/);
      await assert.rejects(ok(A, c => c.query("UPDATE heard_cases SET visibility='public' WHERE id=$1", [CA])), { code: '42501' });
      await assert.rejects(ok(A, c => c.query("INSERT INTO heard_cases(subject_id, kind, status) VALUES($1,'question','review')", [A.subjectId])), { code: '42501' });
      await assert.rejects(ok(A, c => c.query("INSERT INTO heard_cases(subject_id, kind) VALUES($1,'question')", [B.subjectId])), { code: '42501' });
    });

    await t.test('helpers: single object, revocable, expiring; never the case', async () => {
      const grant = await ok(A, c => createGrant(c, A, { caseId: CA, objectId: OA, recipientId: H.subjectId, purpose: 'synthetic review of one file', expiresAt: hour() }));
      await ok(H, c => authorizeObject(c, H, 'evidence.read', OA));
      await denied(ok(H, c => authorizeObject(c, H, 'evidence.read', OA2)), 'other object in same case');
      await denied(ok(H, c => authorizeCase(c, H, 'case.read', CA)), 'object grant is not case access');
      const objects = await ok(H, c => c.query('SELECT id FROM heard_private_objects'));
      assert.deepEqual(objects.rows.map(r => r.id), [OA]);
      await denied(ok(H, c => revokeGrant(c, H, grant)), 'recipient cannot alter the grant');
      await ok(A, c => revokeGrant(c, A, grant));
      await denied(ok(H, c => authorizeObject(c, H, 'evidence.read', OA)), 'revocation is immediate');
      assert.equal((await ok(H, c => c.query('SELECT id FROM heard_private_objects'))).rows.length, 0, 'RLS also hides revoked object');
      await assert.rejects(ok(A, c => createGrant(c, A, { caseId: CA, objectId: OA, recipientId: A.subjectId, purpose: 'self', expiresAt: hour() })), { code: '42501' });
      await denied(ok(A, c => createGrant(c, A, { caseId: CA, objectId: OA, recipientId: H.subjectId, purpose: 'too long', expiresAt: new Date(Date.now() + 365 * 86_400_000) })));
      await denied(ok(B, c => createGrant(c, B, { caseId: CA, objectId: OA, recipientId: B.subjectId, purpose: 'forged', expiresAt: hour() })), 'non-owner cannot grant');
      await assert.rejects(ok(B, c => c.query("INSERT INTO heard_resource_grants(case_id, object_id, grantor_id, recipient_id, action, purpose, expires_at) VALUES($1,$2,$3,$4,'read','forged',now()+interval '1 hour')", [CA, OA, A.subjectId, B.subjectId])), { code: '42501' }, 'forging grantor fails in the database');
    });

    await t.test('vertical: staff need MFA, a role and an assignment; administrator alone sees nothing', async () => {
      await denied(ok(R, c => authorizeCase(c, R, 'review.read_case', CA)), 'unassigned');
      await assignStaff(h.pool, { caseId: CA, staffSubjectId: R.subjectId, role: 'reviewer', purpose: 'synthetic assignment', expiresAt: hour() });
      await ok(R, c => authorizeCase(c, R, 'review.read_case', CA));
      await ok(R, c => authorizeObject(c, R, 'evidence.read', OA));
      await denied(ok(R, c => authorizeCase(c, R, 'review.read_case', CB)), 'other case');
      await denied(ok({ ...R, assurance: 'anonymous_recovery' }, c => authorizeCase(c, R, 'review.read_case', CA)), 'no MFA');
      assert.equal((await ok({ ...R, assurance: 'anonymous_recovery' }, c => c.query('SELECT id FROM heard_cases'))).rows.length, 0, 'RLS needs MFA assurance too');
      await denied(ok(R2, c => authorizeCase(c, R2, 'review.read_case', CA)));
      await denied(ok(ADM, c => authorizeCase(c, ADM, 'review.read_case', CA)));
      assert.equal((await ok(ADM, c => c.query('SELECT id FROM heard_cases'))).rows.length, 0);
      await assert.rejects(assignStaff(h.pool, { caseId: CA, staffSubjectId: ADM.subjectId, role: 'reviewer', purpose: 'wrong role', expiresAt: hour() }), { code: 'NOT_FOUND' });
      await ok(R, c => adapter.startReview(c, { caseId: CA, actorId: R.subjectId }));
      assert.equal((await ok(A, c => adapter.readStatus(c, { caseId: CA }))).status, 'review');
    });

    await t.test('nobody reviews their own case', async () => {
      const ownerStaff = await staff('reviewer');
      const own = randomUUID();
      await ok(ownerStaff, async c => { await adapter.createDraft(c, { caseId: own, subjectId: ownerStaff.subjectId, kind: 'question' }); await adapter.submit(c, { caseId: own, actorId: ownerStaff.subjectId, policyVersion: 'v1' }); });
      await assert.rejects(assignStaff(h.pool, { caseId: own, staffSubjectId: ownerStaff.subjectId, role: 'reviewer', purpose: 'self review', expiresAt: hour() }), /own case/);
      await denied(ok(ownerStaff, c => authorizeCase(c, ownerStaff, 'review.read_case', own)));
    });

    await t.test('denials are audited without confirming existence', async () => {
      const rows = (await h.admin.query("SELECT actor_id, case_id, action, metadata FROM heard_audit_events WHERE outcome='deny' AND action LIKE 'authz.%'")).rows;
      assert.ok(rows.length >= 5);
      assert.ok(rows.every(r => r.case_id === null && typeof r.metadata.reason === 'string'));
      assert.ok(rows.some(r => r.actor_id === H.subjectId && r.metadata.target === OA));
    });
  } finally {
    await h.stop();
  }
});
