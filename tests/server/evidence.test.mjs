import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { startHarness, client, ORIGIN } from './harness.mjs';
import { processScanJobs, createFakeScanner } from '../../packages/quarantine/src/index.mjs';
import { resolveSession, provisionStaff, startStaffSession } from '../../packages/identity/src/index.mjs';
import { withSession, createGrant, assignStaff } from '../../packages/authorization/src/index.mjs';
import { CONSENT_POLICIES } from '../../packages/consent/src/index.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('synthetic evidence image')]);

test('evidence integrity, provenance and chain of handling on native PostgreSQL', async t => {
  const h = await startHarness('heard_test_evidence', { HEARD_OBJECT_STORAGE_DRIVER: 'memory' });
  const storage = h.app.context.storage;
  const secret = h.config.secrets.sessionSecret;
  const owner = client(h.app);
  await owner.request('POST', '/api/v1/anonymous/start', {});
  const caseId = (await owner.request('POST', '/api/v1/drafts', { kind: 'experience' })).body.caseId;
  const upload = async bytes => {
    const start = await owner.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type: 'image/png', size: bytes.length, sha256: sha(bytes) });
    await h.app.handle(new Request(`${ORIGIN}/api/v1/uploads/${start.body.uploadId}/parts/1`, { method: 'PUT', body: bytes, headers: { origin: ORIGIN, cookie: owner.cookie, 'content-type': 'application/octet-stream' } }));
    return (await owner.request('POST', `/api/v1/uploads/${start.body.uploadId}/complete`, {})).body.objectId;
  };
  const download = (id, who) => h.app.handle(new Request(`${ORIGIN}/api/v1/objects/${id}`, { headers: { cookie: who.cookie } }));
  const events = async id => (await h.admin.query('SELECT ordinal, operation, actor_kind, detail FROM heard_evidence_events WHERE object_id=$1 ORDER BY ordinal', [id])).rows;
  try {
    const objectId = await upload(PNG);
    const second = await upload(Buffer.concat([PNG, Buffer.from('2')]));
    await processScanJobs(h.pool, { storage, scanner: createFakeScanner(), limit: 10 });
    const manifestPath = `/api/v1/my/cases/${caseId}/evidence-manifest`;

    await t.test('receipt and scan are recorded in order by the database', async () => {
      assert.deepEqual((await events(objectId)).map(e => [e.ordinal, e.operation, e.actor_kind]), [[1, 'received', 'contributor'], [2, 'scan_cleared', 'service']]);
      assert.deepEqual((await events(objectId))[1].detail, { engine: 'fake-eicar/1' });
    });

    await t.test('downloads by contributor, assigned staff and helper are attributed by kind', async () => {
      assert.equal((await download(objectId, owner)).status, 200);
      const ownerSession = await resolveSession(h.pool, owner.cookie.split('=')[1], { secret });
      const helper = client(h.app); await helper.request('POST', '/api/v1/anonymous/start', {});
      const helperSession = await resolveSession(h.pool, helper.cookie.split('=')[1], { secret });
      await withSession(h.pool, ownerSession, c => createGrant(c, ownerSession, { caseId, objectId, recipientId: helperSession.subjectId, purpose: 'synthetic review', expiresAt: new Date(Date.now() + 3_600_000) }));
      assert.equal((await download(objectId, helper)).status, 200);
      assert.equal((await helper.request('GET', manifestPath)).status, 404, 'helpers do not see the case ledger');
      await owner.request('PUT', `/api/v1/drafts/${caseId}`, { revision: 0, answers: { identity_mode: 'private', narrative: 'Synthetic narrative that must never reach a manifest.' } });
      await owner.request('POST', `/api/v1/my/cases/${caseId}/consents`, { purpose: 'private_processing', decision: 'grant', policyVersion: CONSENT_POLICIES.private_processing.version });
      assert.equal((await owner.request('POST', `/api/v1/drafts/${caseId}/submit`, { revision: 1 }, { 'idempotency-key': randomUUID() })).status, 201);
      const staffId = await provisionStaff(h.pool, { role: 'reviewer', purpose: 'synthetic review', expiresAt: new Date(Date.now() + 86_400_000) });
      await assignStaff(h.pool, { caseId, staffSubjectId: staffId, role: 'reviewer', purpose: 'synthetic review', expiresAt: new Date(Date.now() + 3_600_000) });
      const staff = client(h.app); staff.cookie = `__Host-heard_session=${(await startStaffSession(h.pool, staffId, { secret, mfaVerified: true })).token}`;
      assert.equal((await download(objectId, staff)).status, 200);
      assert.deepEqual((await events(objectId)).slice(2).map(e => [e.operation, e.actor_kind]), [['downloaded', 'contributor'], ['downloaded', 'helper'], ['downloaded', 'staff']]);
      assert.equal((await staff.request('GET', manifestPath)).status, 200, 'assigned staff can export the manifest');
    });

    await t.test('contributor source statements are recorded as claims, validated and owner-only', async () => {
      assert.equal((await owner.request('POST', `/api/v1/objects/${objectId}/source`, { source: 'self_recorded', captured: '2026-03' })).status, 201);
      assert.equal((await owner.request('POST', `/api/v1/objects/${objectId}/source`, { source: 'verified_by_heard' })).status, 400);
      assert.equal((await owner.request('POST', `/api/v1/objects/${objectId}/source`, { source: 'unknown', captured: 'last spring near my house' })).status, 400);
      const intruder = client(h.app); await intruder.request('POST', '/api/v1/anonymous/start', {});
      assert.equal((await intruder.request('POST', `/api/v1/objects/${objectId}/source`, { source: 'unknown' })).status, 404);
    });

    await t.test('the manifest lists digests and a valid ledger, with no keys, narrative or identities', async () => {
      const res = await owner.request('GET', manifestPath);
      assert.equal(res.status, 200);
      const m = res.body;
      assert.match(m.notice, /does not establish that any file is authentic/);
      const entry = m.objects.find(o => o.objectId === objectId);
      assert.equal(entry.sha256, sha(PNG));
      assert.equal(entry.ledger.valid, true);
      assert.equal(entry.ledger.length, 6);
      assert.deepEqual(entry.contributorSourceStatement, { source: 'self_recorded', captured: '2026-03' });
      const text = JSON.stringify(m);
      assert.doesNotMatch(text, /quarantine\/|storage_ref|Synthetic narrative|actor_?id/i);
      assert.equal((await client(h.app).request('GET', manifestPath)).status, 401);
    });

    await t.test('writers cannot choose hashes, predecessors, service identity or another actor', async () => {
      const s = await resolveSession(h.pool, owner.cookie.split('=')[1], { secret });
      await withSession(h.pool, s, c => c.query("INSERT INTO heard_evidence_events(object_id, case_id, ordinal, operation, actor_kind, actor_id, prev_hash, event_hash) VALUES($1,$2,99,'verified','contributor',$3,repeat('0',64),repeat('1',64))", [second, caseId, s.subjectId]));
      const last = (await h.admin.query('SELECT ordinal, prev_hash, event_hash FROM heard_evidence_events WHERE object_id=$1 ORDER BY ordinal DESC LIMIT 1', [second])).rows[0];
      assert.equal(last.ordinal, 3); assert.notEqual(last.event_hash, '1'.repeat(64)); assert.notEqual(last.prev_hash, '0'.repeat(64));
      await assert.rejects(withSession(h.pool, s, c => c.query("INSERT INTO heard_evidence_events(object_id, case_id, operation, actor_kind) VALUES($1,$2,'scan_cleared','service')", [second, caseId])), { code: '42501' });
      await assert.rejects(withSession(h.pool, s, c => c.query("INSERT INTO heard_evidence_events(object_id, case_id, operation, actor_kind, actor_id) VALUES($1,$2,'verified','staff',$3)", [second, caseId, randomUUID()])), /violates|foreign key|row-level/);
      await withSession(h.pool, s, c => c.query("INSERT INTO heard_evidence_events(object_id, case_id, operation, actor_kind, actor_id) VALUES($1,$2,'verified','staff',$3)", [second, caseId, s.subjectId]));
      assert.equal((await h.admin.query('SELECT actor_kind FROM heard_evidence_events WHERE object_id=$1 ORDER BY ordinal DESC LIMIT 1', [second])).rows[0].actor_kind, 'contributor', 'claimed staff kind is replaced by the derived kind');
      await assert.rejects(h.admin.query('UPDATE heard_evidence_events SET detail=$2 WHERE object_id=$1', [objectId, { reason: 'edited' }]), /append-only/);
    });

    await t.test('originals are immutable and cannot be deleted', async () => {
      await assert.rejects(h.admin.query("UPDATE heard_private_objects SET checksum_sha256=repeat('a',64) WHERE id=$1", [objectId]), /immutable/);
      await assert.rejects(h.admin.query("UPDATE heard_private_objects SET storage_ref='quarantine/00000000-0000-4000-8000-000000000000' WHERE id=$1", [objectId]), /immutable/);
      await assert.rejects(h.admin.query('DELETE FROM heard_private_objects WHERE id=$1', [objectId]), /cannot be deleted/);
    });

    await t.test('changed bytes fail verification and the failure is itself recorded', async () => {
      assert.deepEqual((await owner.request('POST', `/api/v1/objects/${objectId}/verify`, {})).body.matches, true);
      const key = (await h.admin.query('SELECT storage_ref FROM heard_private_objects WHERE id=$1', [objectId])).rows[0].storage_ref;
      storage._objects.get(key)[3] ^= 0x01;
      assert.equal((await owner.request('POST', `/api/v1/objects/${objectId}/verify`, {})).body.matches, false);
      assert.deepEqual((await events(objectId)).slice(-2).map(e => e.operation), ['verified', 'verification_failed']);
    });

    await t.test('ledger tampering by a privileged database actor is detected', async () => {
      await h.admin.query('ALTER TABLE heard_evidence_events DISABLE TRIGGER heard_evidence_append_only');
      await h.admin.query("UPDATE heard_evidence_events SET actor_kind='contributor', actor_id=(SELECT subject_id FROM heard_cases WHERE id=$2) WHERE object_id=$1 AND ordinal=2", [objectId, caseId]);
      await h.admin.query('DELETE FROM heard_evidence_events WHERE object_id=$1 AND ordinal=2', [second]);
      await h.admin.query('ALTER TABLE heard_evidence_events ENABLE TRIGGER heard_evidence_append_only');
      const m = (await owner.request('GET', manifestPath)).body;
      const altered = m.objects.find(o => o.objectId === objectId).ledger;
      assert.equal(altered.valid, false);
      assert.ok(altered.problems.includes('altered_event_2'));
      const gapped = m.objects.find(o => o.objectId === second).ledger;
      assert.equal(gapped.valid, false);
      assert.ok(gapped.problems.some(p => p.startsWith('gap_at') || p.startsWith('broken_link')));
    });
  } finally {
    await h.stop();
  }
});
