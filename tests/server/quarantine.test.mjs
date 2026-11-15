import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { startHarness, client, ORIGIN } from './harness.mjs';
import { processScanJobs, createFakeScanner, createNoScanner, EICAR } from '../../packages/quarantine/src/index.mjs';
import { resolveSession } from '../../packages/identity/src/index.mjs';
import { withSession, createGrant } from '../../packages/authorization/src/index.mjs';
import { withScope } from '../../packages/database/src/index.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('synthetic png body bytes')]);
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from('synthetic jpeg body')]);

test('quarantine, scanning and safe delivery on native PostgreSQL', async t => {
  const h = await startHarness('heard_test_quarantine', { HEARD_OBJECT_STORAGE_DRIVER: 'memory' });
  const storage = h.app.context.storage;
  const secret = h.config.secrets.sessionSecret;
  const c = client(h.app);
  await c.request('POST', '/api/v1/anonymous/start', {});
  const caseId = (await c.request('POST', '/api/v1/drafts', { kind: 'experience' })).body.caseId;
  const upload = async (type, bytes, who = c) => {
    const start = await who.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type, size: bytes.length, sha256: sha(bytes) });
    assert.equal(start.status, 201, JSON.stringify(start.body));
    const put = await h.app.handle(new Request(`${ORIGIN}/api/v1/uploads/${start.body.uploadId}/parts/1`, { method: 'PUT', body: bytes, headers: { origin: ORIGIN, cookie: who.cookie, 'content-type': 'application/octet-stream' } }));
    assert.equal(put.status, 200);
    const done = await who.request('POST', `/api/v1/uploads/${start.body.uploadId}/complete`, {});
    assert.equal(done.status, 201);
    return done.body.objectId;
  };
  const state = async id => (await h.admin.query('SELECT quarantine_state, quarantine_reason, scan_verdict, detected_type FROM heard_private_objects WHERE id=$1', [id])).rows[0];
  const download = (id, who = c) => h.app.handle(new Request(`${ORIGIN}/api/v1/objects/${id}`, { headers: { cookie: who.cookie } }));
  try {
    const clean = await upload('image/png', PNG);
    const infected = await upload('image/jpeg', Buffer.concat([JPEG, Buffer.from(EICAR)]));
    const mislabeled = await upload('image/png', JPEG);
    const activePdf = await upload('application/pdf', Buffer.from('%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj'));
    const tampered = await upload('application/pdf', Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj'));

    await t.test('every completed upload is queued for scanning and unreadable until cleared', async () => {
      assert.equal((await h.admin.query("SELECT count(*)::int AS n FROM heard_jobs WHERE kind='scan' AND state='queued'")).rows[0].n, 5);
      const res = await download(clean);
      assert.equal(res.status, 409, 'owner cannot download quarantined bytes');
      const list = await c.request('GET', `/api/v1/my/cases/${caseId}/objects`);
      assert.ok(list.body.objects.every(o => o.state === 'quarantined' && !('storageRef' in o)));
    });

    await t.test('without a scanner nothing is cleared; retries back off and finally fail closed', async () => {
      const results = await processScanJobs(h.pool, { storage, scanner: createNoScanner(), limit: 10 });
      assert.equal(results.length, 5);
      // Deterministic content checks reject without a scanner; nothing can be cleared without one.
      const byObject = Object.fromEntries(results.map(r => [r.objectId, `${r.state}:${r.reason}`]));
      assert.equal(byObject[mislabeled], 'rejected:type_mismatch');
      assert.equal(byObject[activePdf], 'rejected:pdf_active_content');
      for (const id of [clean, infected, tampered]) assert.equal(byObject[id], 'retry:SCANNER_UNAVAILABLE');
      assert.ok(results.every(r => r.state !== 'cleared'));
      assert.equal((await state(clean)).quarantine_state, 'quarantined');
      assert.equal((await state(clean)).quarantine_reason, 'scan_pending');
      assert.deepEqual(await processScanJobs(h.pool, { storage, scanner: createNoScanner() }), [], 'backoff delays the retry');
      await h.admin.query("UPDATE heard_jobs SET available_at=now() WHERE kind='scan'");
    });

    await t.test('storage tampering after upload is detected by digest re-verification', async () => {
      const key = (await h.admin.query('SELECT storage_ref FROM heard_private_objects WHERE id=$1', [tampered])).rows[0].storage_ref;
      const bytes = storage._objects.get(key); bytes[bytes.length - 1] ^= 0xff;
    });

    await t.test('fake scanner pass: clean cleared; malware, mislabeled, active PDF and tampered rejected', async () => {
      const [a, b] = await Promise.all([
        processScanJobs(h.pool, { storage, scanner: createFakeScanner(), limit: 10 }),
        processScanJobs(h.pool, { storage, scanner: createFakeScanner(), limit: 10 }),
      ]);
      assert.equal(a.length + b.length, 3, 'concurrent workers process each remaining job exactly once');
      assert.deepEqual(await state(clean), { quarantine_state: 'cleared', quarantine_reason: null, scan_verdict: 'clean', detected_type: 'image/png' });
      assert.deepEqual(await state(infected), { quarantine_state: 'rejected', quarantine_reason: 'malware', scan_verdict: 'infected', detected_type: 'image/jpeg' });
      assert.equal((await state(mislabeled)).quarantine_reason, 'type_mismatch');
      assert.equal((await state(activePdf)).quarantine_reason, 'pdf_active_content');
      assert.equal((await state(tampered)).quarantine_reason, 'integrity_mismatch');
      assert.equal((await h.admin.query("SELECT count(*)::int AS n FROM heard_jobs WHERE kind='scan' AND state='succeeded'")).rows[0].n, 5);
    });

    await t.test('only cleared bytes are served, as a sandboxed attachment', async () => {
      const res = await download(clean);
      assert.equal(res.status, 200);
      assert.ok(Buffer.from(await res.arrayBuffer()).equals(PNG));
      assert.equal(res.headers.get('content-type'), 'image/png');
      assert.match(res.headers.get('content-disposition'), /^attachment; filename="heard-[0-9a-f-]{36}\.png"$/);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.match(res.headers.get('content-security-policy'), /sandbox/);
      assert.equal(res.headers.get('cache-control'), 'no-store');
      for (const id of [infected, mislabeled, activePdf, tampered]) assert.equal((await download(id)).status, 409);
    });

    await t.test('others need an explicit grant; a grant does not unlock unscanned or rejected objects', async () => {
      const helper = client(h.app);
      await helper.request('POST', '/api/v1/anonymous/start', {});
      assert.equal((await download(clean, helper)).status, 404);
      const owner = await resolveSession(h.pool, c.cookie.split('=')[1], { secret });
      const helperSession = await resolveSession(h.pool, helper.cookie.split('=')[1], { secret });
      await withSession(h.pool, owner, x => createGrant(x, owner, { caseId, objectId: clean, recipientId: helperSession.subjectId, purpose: 'synthetic helper review', expiresAt: new Date(Date.now() + 3_600_000) }));
      await withSession(h.pool, owner, x => createGrant(x, owner, { caseId, objectId: infected, recipientId: helperSession.subjectId, purpose: 'synthetic helper review', expiresAt: new Date(Date.now() + 3_600_000) }));
      assert.equal((await download(clean, helper)).status, 200);
      assert.equal((await download(infected, helper)).status, 409);
      assert.equal((await helper.request('GET', `/api/v1/my/cases/${caseId}/objects`)).status, 404, 'grant is per object, not the case listing');
    });

    await t.test('the database refuses to clear an object without a clean verdict and verified type', async () => {
      const fresh = await upload('image/png', Buffer.concat([PNG, Buffer.from('second')]));
      await assert.rejects(h.admin.query("UPDATE heard_private_objects SET quarantine_state='cleared' WHERE id=$1", [fresh]), { code: '23514' });
      await assert.rejects(h.admin.query("UPDATE heard_private_objects SET quarantine_state='cleared', scan_verdict='clean', scan_engine='x', scanned_at=now(), detected_type='image/jpeg' WHERE id=$1", [fresh]), { code: '23514' }, 'type must match declaration');
      const seen = await withScope(h.pool, { role: 'heard_job_worker' }, x => x.query('SELECT id FROM heard_private_objects'));
      assert.equal(seen.rows.length, 0, 'worker without declared purpose sees nothing');
      const contributor = await resolveSession(h.pool, c.cookie.split('=')[1], { secret });
      await assert.rejects(withSession(h.pool, contributor, x => x.query("UPDATE heard_private_objects SET quarantine_state='cleared' WHERE id=$1", [fresh])), { code: '42501' }, 'contributors cannot self-clear');
      await assert.rejects(withSession(h.pool, contributor, x => x.query("INSERT INTO heard_jobs(case_id, object_id, kind, dedupe_key, state, lease_owner, lease_until) VALUES($1,$2,'scan',$3,'leased',$4,now())", [caseId, fresh, `x:${randomUUID()}`, randomUUID()])), { code: '42501' }, 'contributors can only enqueue fresh scans');
    });

    await t.test('an expired lease is recovered by another worker; exhausted jobs fail closed', async () => {
      const id = await upload('image/png', Buffer.concat([PNG, Buffer.from('third')]));
      await h.admin.query("UPDATE heard_jobs SET state='leased', lease_owner=$2, lease_until=now()-interval '1 minute', attempts=1 WHERE object_id=$1", [id, randomUUID()]);
      const recovered = await processScanJobs(h.pool, { storage, scanner: createFakeScanner() });
      assert.ok(recovered.some(r => r.objectId === id && r.state === 'cleared'));
      const stuck = await upload('image/png', Buffer.concat([PNG, Buffer.from('fourth')]));
      for (let i = 0; i < 4; i++) {
        await processScanJobs(h.pool, { storage, scanner: createFakeScanner({ fail: true }) });
        await h.admin.query("UPDATE heard_jobs SET available_at=now() WHERE object_id=$1", [stuck]);
      }
      assert.equal((await h.admin.query('SELECT state, last_error_code FROM heard_jobs WHERE object_id=$1', [stuck])).rows[0].state, 'failed');
      assert.deepEqual(await state(stuck), { quarantine_state: 'quarantined', quarantine_reason: 'scan_failed', scan_verdict: 'error', detected_type: null });
      assert.deepEqual(await processScanJobs(h.pool, { storage, scanner: createFakeScanner() }), [], 'failed jobs are not retried silently');
    });
  } finally {
    await h.stop();
  }
});
