/**
 * HEARD-12 resumable private uploads.
 *
 * A contributor declares type, size and SHA-256 up front for a draft case they
 * own. Bytes arrive in fixed-size parts through the HEARD API (never via a public
 * or long-lived URL) into an opaque quarantine key. Completion re-reads the
 * assembled object and accepts it only if size and digest match exactly; the
 * object is then recorded as `quarantined` and is not readable until HEARD-13's
 * scanner clears it. Nothing about the original filename is stored.
 */
import { createHash } from 'node:crypto';
import { authorizeCase, withSession } from '@heard/authorization';
import { withScope } from '@heard/database';
import { audit } from '@heard/identity';
import { digestObject, quarantineKey } from '@heard/storage';

const MiB = 1024 * 1024;
export const CHUNK_SIZE = 5 * MiB;
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
/** Allowlisted media types, their size ceilings and per-draft quotas (pilot defaults, DEVELOPMENT_PLAN §9). */
export const MEDIA_TYPES = Object.freeze({
  'image/jpeg': { group: 'document', maxBytes: 25 * MiB },
  'image/png': { group: 'document', maxBytes: 25 * MiB },
  'application/pdf': { group: 'document', maxBytes: 25 * MiB },
  'video/mp4': { group: 'video', maxBytes: 300 * MiB },
  'video/quicktime': { group: 'video', maxBytes: 300 * MiB },
  'audio/mpeg': { group: 'audio', maxBytes: 100 * MiB },
  'audio/mp4': { group: 'audio', maxBytes: 100 * MiB },
});
export const GROUP_QUOTAS = Object.freeze({ document: 10, video: 1, audio: 2 });

export class UploadError extends Error {
  constructor(code, field) { super(code); this.code = code; this.field = field; }
}

export function partLength(session, partNumber) {
  if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > session.partCount) return null;
  return partNumber < session.partCount ? session.chunkSize : session.declaredSize - session.chunkSize * (session.partCount - 1);
}

export function validateDeclaration({ type, size, sha256 }) {
  const media = MEDIA_TYPES[type];
  if (!media) throw new UploadError('UPLOAD_TYPE_NOT_ALLOWED', 'type');
  if (!Number.isSafeInteger(size) || size <= 0 || size > media.maxBytes) throw new UploadError('UPLOAD_SIZE_NOT_ALLOWED', 'size');
  if (typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sha256)) throw new UploadError('UPLOAD_DIGEST_INVALID', 'sha256');
  return { type, size, sha256, group: media.group, partCount: Math.ceil(size / CHUNK_SIZE) };
}

const toSession = r => r && ({ id: r.id, caseId: r.case_id, declaredType: r.declared_type, declaredSize: Number(r.declared_size), expectedSha256: r.expected_sha256, chunkSize: r.chunk_size, partCount: r.part_count, storageKey: r.storage_key, storageUploadId: r.storage_upload_id, state: r.state, objectId: r.object_id, rejection: r.rejection, expiresAt: r.expires_at });

export function createUploadService({ pool, storage, onObjectQuarantined = async () => {} }) {
  if (!storage) throw new UploadError('UPLOADS_UNAVAILABLE');

  async function loadOpen(client, session, uploadId, now) {
    const s = toSession((await client.query('SELECT * FROM heard_upload_sessions WHERE id=$1 FOR UPDATE', [uploadId])).rows[0]);
    if (!s) throw new UploadError('NOT_FOUND');
    await authorizeCase(client, session, 'evidence.upload', s.caseId, { now });
    if (s.state !== 'open') throw new UploadError('UPLOAD_NOT_OPEN');
    if (s.expiresAt <= now) throw new UploadError('UPLOAD_EXPIRED');
    return s;
  }

  return {
    async start(session, caseId, declaration, { now = new Date() } = {}) {
      const d = validateDeclaration(declaration);
      // Reserve the quota and record the session before any storage call; abandoned
      // storage uploads are cleaned up by the expiry job.
      const key = quarantineKey();
      const storageUploadId = await storage.createMultipart(key);
      try {
        return await withSession(pool, session, async client => {
          await authorizeCase(client, session, 'evidence.upload', caseId, { now });
          await client.query('SELECT 1 FROM heard_cases WHERE id=$1 FOR UPDATE', [caseId]);
          const used = (await client.query("SELECT declared_type FROM heard_upload_sessions WHERE case_id=$1 AND state IN ('open','completing','completed')", [caseId])).rows
            .filter(r => MEDIA_TYPES[r.declared_type]?.group === d.group).length;
          if (used >= GROUP_QUOTAS[d.group]) throw new UploadError('UPLOAD_QUOTA_REACHED', 'type');
          const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);
          const row = (await client.query(
            'INSERT INTO heard_upload_sessions(case_id, subject_id, declared_type, declared_size, expected_sha256, chunk_size, part_count, storage_key, storage_upload_id, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',
            [caseId, session.subjectId, d.type, d.size, d.sha256, CHUNK_SIZE, d.partCount, key, storageUploadId, expiresAt])).rows[0];
          await audit(client, session.subjectId, 'upload.started', 'allow', { caseId, metadata: { reason: d.group } });
          return { uploadId: row.id, chunkSize: CHUNK_SIZE, partCount: d.partCount, expiresAt };
        });
      } catch (error) {
        await storage.abortMultipart(key, storageUploadId).catch(() => {});
        throw error;
      }
    },

    /** Upload (or re-upload) one part. Length must match exactly; re-sending a part replaces it. */
    async putPart(session, uploadId, partNumber, bytes, { now = new Date() } = {}) {
      return withSession(pool, session, async client => {
        const s = await loadOpen(client, session, uploadId, now);
        const expected = partLength(s, partNumber);
        if (expected === null) throw new UploadError('UPLOAD_PART_INVALID', 'part');
        if (!Buffer.isBuffer(bytes) || bytes.length !== expected) throw new UploadError('UPLOAD_PART_SIZE', 'part');
        const etag = await storage.uploadPart(s.storageKey, s.storageUploadId, partNumber, bytes);
        const digest = createHash('sha256').update(bytes).digest('hex');
        await client.query(
          `INSERT INTO heard_upload_parts(session_id, part_number, size, sha256, etag) VALUES($1,$2,$3,$4,$5)
           ON CONFLICT (session_id, part_number) DO UPDATE SET size=EXCLUDED.size, sha256=EXCLUDED.sha256, etag=EXCLUDED.etag, uploaded_at=now()`,
          [uploadId, partNumber, bytes.length, digest, etag]);
        return { partNumber, sha256: digest };
      });
    },

    async status(session, uploadId) {
      return withSession(pool, session, async client => {
        const s = toSession((await client.query('SELECT * FROM heard_upload_sessions WHERE id=$1', [uploadId])).rows[0]);
        if (!s) throw new UploadError('NOT_FOUND');
        const parts = (await client.query('SELECT part_number FROM heard_upload_parts WHERE session_id=$1 ORDER BY part_number', [uploadId])).rows.map(r => r.part_number);
        return { uploadId, state: s.state, partCount: s.partCount, chunkSize: s.chunkSize, receivedParts: parts, objectId: s.objectId, rejection: s.rejection, expiresAt: s.expiresAt };
      });
    },

    /** Assemble, verify size and digest against the declaration, then record a quarantined object. */
    async complete(session, uploadId, { now = new Date() } = {}) {
      const s = await withSession(pool, session, async client => {
        const open = await loadOpen(client, session, uploadId, now);
        const parts = (await client.query('SELECT part_number, etag FROM heard_upload_parts WHERE session_id=$1 ORDER BY part_number', [uploadId])).rows;
        if (parts.length !== open.partCount || parts.some((p, i) => p.part_number !== i + 1)) throw new UploadError('UPLOAD_PARTS_MISSING');
        await client.query("UPDATE heard_upload_sessions SET state='completing' WHERE id=$1 AND state='open'", [uploadId]);
        return { ...open, parts: parts.map(p => ({ partNumber: p.part_number, etag: p.etag })) };
      });
      let rejection = null;
      try {
        await storage.completeMultipart(s.storageKey, s.storageUploadId, s.parts);
        const actual = await digestObject(storage, s.storageKey, { maxBytes: s.declaredSize });
        if (actual.size !== s.declaredSize) rejection = 'size_mismatch';
        else if (actual.sha256 !== s.expectedSha256) rejection = 'digest_mismatch';
      } catch (error) {
        rejection = error?.code === 'STORAGE_OBJECT_TOO_LARGE' ? 'size_mismatch' : 'assembly_failed';
      }
      if (rejection) {
        await storage.deleteObject(s.storageKey).catch(() => {});
        await withSession(pool, session, c => c.query("UPDATE heard_upload_sessions SET state='rejected', rejection=$2 WHERE id=$1", [uploadId, rejection]));
        throw new UploadError(rejection === 'assembly_failed' ? 'UPLOAD_ASSEMBLY_FAILED' : 'UPLOAD_INTEGRITY_FAILED');
      }
      return withSession(pool, session, async client => {
        const object = (await client.query(
          "INSERT INTO heard_private_objects(case_id, storage_ref, checksum_sha256, quarantine_state, declared_type, size_bytes, upload_session_id, created_by) VALUES($1,$2,$3,'quarantined',$4,$5,$6,$7) RETURNING id",
          [s.caseId, s.storageKey, s.expectedSha256, s.declaredType, s.declaredSize, uploadId, session.subjectId])).rows[0];
        await client.query("UPDATE heard_upload_sessions SET state='completed', object_id=$2, completed_at=$3 WHERE id=$1 AND state='completing'", [uploadId, object.id, now]);
        await onObjectQuarantined(client, { objectId: object.id, caseId: s.caseId, actorId: session.subjectId });
        await audit(client, session.subjectId, 'upload.completed', 'allow', { caseId: s.caseId, metadata: { reason: 'quarantined' } });
        return { objectId: object.id, state: 'quarantined', sha256: s.expectedSha256, size: s.declaredSize };
      });
    },

    async abort(session, uploadId, { now = new Date() } = {}) {
      const s = await withSession(pool, session, async client => {
        const open = await loadOpen(client, session, uploadId, now);
        await client.query("UPDATE heard_upload_sessions SET state='aborted' WHERE id=$1", [uploadId]);
        return open;
      });
      await storage.abortMultipart(s.storageKey, s.storageUploadId).catch(() => {});
      return { uploadId, state: 'aborted' };
    },
  };
}

/** Job: expire abandoned sessions and release their storage. Runs as heard_job_worker. */
export async function expireUploadSessions(pool, storage) {
  const expired = await withScope(pool, { role: 'heard_job_worker', settings: { job_purpose: 'upload_expiry' } }, async client => {
    const rows = (await client.query("SELECT id, storage_key, storage_upload_id FROM heard_upload_sessions WHERE state='open' FOR UPDATE SKIP LOCKED")).rows;
    if (rows.length) await client.query("UPDATE heard_upload_sessions SET state='expired' WHERE id = ANY($1::uuid[])", [rows.map(r => r.id)]);
    return rows;
  });
  for (const r of expired) await storage.abortMultipart(r.storage_key, r.storage_upload_id).catch(() => {});
  return expired.length;
}
