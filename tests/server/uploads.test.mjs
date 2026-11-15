import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { startHarness, client, ORIGIN } from './harness.mjs';
import { CHUNK_SIZE, expireUploadSessions } from '../../packages/uploads/src/index.mjs';
import { CONSENT_POLICIES } from '../../packages/consent/src/index.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');
const putPart = (h, c, uploadId, n, bytes, headers = {}) => h.app.handle(new Request(`${ORIGIN}/api/v1/uploads/${uploadId}/parts/${n}`, {
  method: 'PUT', body: bytes, headers: { origin: ORIGIN, cookie: c.cookie, 'content-type': 'application/octet-stream', ...headers },
}));

test('resumable private uploads into quarantine on native PostgreSQL', async t => {
  const h = await startHarness('heard_test_uploads', { HEARD_OBJECT_STORAGE_DRIVER: 'memory' });
  const storage = h.app.context.storage;
  const contributor = async () => {
    const c = client(h.app);
    await c.request('POST', '/api/v1/anonymous/start', {});
    const caseId = (await c.request('POST', '/api/v1/drafts', { kind: 'experience' })).body.caseId;
    return { c, caseId };
  };
  try {
    const { c, caseId } = await contributor();
    const file = Buffer.concat([Buffer.from('%PDF-1.7\n'), randomBytes(CHUNK_SIZE + 1000)]);
    let uploadId;

    await t.test('declaration is validated against the allowlist and limits', async () => {
      const base = `/api/v1/drafts/${caseId}/uploads`;
      assert.equal((await c.request('POST', base, { type: 'application/x-msdownload', size: 10, sha256: sha('x') })).status, 400);
      assert.equal((await c.request('POST', base, { type: 'application/pdf', size: 26 * 1024 * 1024, sha256: sha('x') })).status, 400);
      assert.equal((await c.request('POST', base, { type: 'application/pdf', size: 10, sha256: 'nothex' })).status, 400);
      assert.equal((await c.request('POST', base, { type: 'application/pdf', size: 10, sha256: sha('x'), filename: 'my-name.pdf' })).status, 400, 'filenames are not accepted');
      const ok = await c.request('POST', base, { type: 'application/pdf', size: file.length, sha256: sha(file) });
      assert.equal(ok.status, 201);
      assert.equal(ok.body.partCount, 2);
      assert.equal(ok.body.chunkSize, CHUNK_SIZE);
      uploadId = ok.body.uploadId;
    });

    await t.test('parts are exact-length, owner-only, same-origin and resumable in any order', async () => {
      const part1 = file.subarray(0, CHUNK_SIZE); const part2 = file.subarray(CHUNK_SIZE);
      assert.equal((await putPart(h, c, uploadId, 2, part1)).status, 400, 'wrong length for last part');
      assert.equal((await putPart(h, c, uploadId, 3, part2)).status, 400, 'out of range');
      assert.equal((await putPart(h, c, uploadId, 2, part2, { 'content-type': 'text/plain' })).status, 415);
      assert.equal((await putPart(h, c, uploadId, 2, part2, { origin: 'https://evil.example' })).status, 403);
      const intruder = await contributor();
      assert.equal((await putPart(h, intruder.c, uploadId, 2, part2)).status, 404);
      assert.equal((await intruder.c.request('GET', `/api/v1/uploads/${uploadId}`)).status, 404);
      assert.equal((await putPart(h, c, uploadId, 2, part2)).status, 200);
      assert.deepEqual((await c.request('GET', `/api/v1/uploads/${uploadId}`)).body.receivedParts, [2]);
      assert.equal((await c.request('POST', `/api/v1/uploads/${uploadId}/complete`, {})).status, 409, 'incomplete');
      assert.equal((await putPart(h, c, uploadId, 1, Buffer.alloc(CHUNK_SIZE))).status, 200, 'a wrong part can be re-sent');
      assert.equal((await putPart(h, c, uploadId, 1, part1)).status, 200);
      assert.deepEqual((await c.request('GET', `/api/v1/uploads/${uploadId}`)).body.receivedParts, [1, 2]);
    });

    await t.test('completion verifies size and digest and records a quarantined object without filename', async () => {
      const done = await c.request('POST', `/api/v1/uploads/${uploadId}/complete`, {});
      assert.equal(done.status, 201);
      assert.equal(done.body.state, 'quarantined');
      const row = (await h.admin.query('SELECT storage_ref, checksum_sha256, quarantine_state, declared_type, size_bytes FROM heard_private_objects WHERE id=$1', [done.body.objectId])).rows[0];
      assert.match(row.storage_ref, /^quarantine\/[0-9a-f-]{36}$/);
      assert.equal(row.checksum_sha256, sha(file));
      assert.equal(row.quarantine_state, 'quarantined');
      assert.equal(Number(row.size_bytes), file.length);
      assert.ok(storage._objects.get(row.storage_ref).equals(file));
      assert.equal((await c.request('POST', `/api/v1/uploads/${uploadId}/complete`, {})).status, 409, 'cannot complete twice');
      const columns = (await h.admin.query("SELECT column_name FROM information_schema.columns WHERE table_name IN ('heard_upload_sessions','heard_private_objects')")).rows.map(r => r.column_name);
      assert.ok(!columns.some(name => /file_?name|original_name|title/.test(name)));
    });

    await t.test('a digest mismatch is rejected and the bytes are deleted', async () => {
      const bytes = Buffer.from('%PDF-1.4 small synthetic file');
      const start = await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type: 'application/pdf', size: bytes.length, sha256: sha('different') });
      assert.equal((await putPart(h, c, start.body.uploadId, 1, bytes)).status, 200);
      const before = storage._objects.size;
      const res = await c.request('POST', `/api/v1/uploads/${start.body.uploadId}/complete`, {});
      assert.equal(res.status, 400);
      assert.equal(res.body.error.fields.file, 'UPLOAD_INTEGRITY_FAILED');
      assert.equal(storage._objects.size, before);
      assert.equal((await c.request('GET', `/api/v1/uploads/${start.body.uploadId}`)).body.rejection, 'digest_mismatch');
    });

    await t.test('per-draft quotas apply by media group', async () => {
      const video = { type: 'video/mp4', size: 1000, sha256: sha('v') };
      assert.equal((await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, video)).status, 201);
      assert.equal((await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, video)).status, 429);
    });

    await t.test('aborted and expired sessions accept nothing more', async () => {
      const a = await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type: 'image/png', size: 10, sha256: sha('p') });
      assert.equal((await c.request('DELETE', `/api/v1/uploads/${a.body.uploadId}`)).status, 200);
      assert.equal((await putPart(h, c, a.body.uploadId, 1, Buffer.alloc(10))).status, 409);
      const e = await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type: 'image/png', size: 10, sha256: sha('q') });
      await h.admin.query("UPDATE heard_upload_sessions SET created_at=now()-interval '2 days', expires_at=now()-interval '1 day' WHERE id=$1", [e.body.uploadId]);
      assert.equal((await putPart(h, c, e.body.uploadId, 1, Buffer.alloc(10))).status, 409);
      assert.equal(await expireUploadSessions(h.pool, storage), 1);
      assert.equal((await h.admin.query('SELECT state FROM heard_upload_sessions WHERE id=$1', [e.body.uploadId])).rows[0].state, 'expired');
    });

    await t.test('uploads close once the case is submitted', async () => {
      await c.request('PUT', `/api/v1/drafts/${caseId}`, { revision: 0, answers: { identity_mode: 'private', narrative: 'Synthetic narrative for the upload test.' } });
      await c.request('POST', `/api/v1/my/cases/${caseId}/consents`, { purpose: 'private_processing', decision: 'grant', policyVersion: CONSENT_POLICIES.private_processing.version });
      assert.equal((await c.request('POST', `/api/v1/drafts/${caseId}/submit`, { revision: 1 }, { 'idempotency-key': randomUUID() })).status, 201);
      assert.equal((await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type: 'image/png', size: 10, sha256: sha('late') })).status, 409);
    });
  } finally {
    await h.stop();
  }
});

test('upload routes do not exist without configured private storage', async () => {
  const h = await startHarness('heard_test_nostorage');
  try {
    const c = client(h.app);
    await c.request('POST', '/api/v1/anonymous/start', {});
    const caseId = (await c.request('POST', '/api/v1/drafts', { kind: 'question' })).body.caseId;
    assert.equal((await c.request('POST', `/api/v1/drafts/${caseId}/uploads`, { type: 'image/png', size: 10, sha256: sha('x') })).status, 404);
  } finally { await h.stop(); }
});
