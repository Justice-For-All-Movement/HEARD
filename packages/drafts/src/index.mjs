/**
 * HEARD-11 secure drafts, recovery and submission receipts.
 *
 * Answers are encrypted with AES-256-GCM (HEARD_DATA_ENCRYPTION_KEY) and bound to
 * their case, schema version and key ID through authenticated data, so a
 * ciphertext cannot be moved to another case. Saves use optimistic revisions;
 * submission is a single transaction that is idempotent per client key.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { authorizeCase, withSession } from '@heard/authorization';
import { requireConsent } from '@heard/consent';
import { withScope } from '@heard/database';
import { audit } from '@heard/identity';
import { INTAKE_SCHEMA_VERSION, KINDS, validateAnswers } from '@heard/intake';

export const DRAFT_TTL_MS = 30 * 86_400_000;
export const MAX_OPEN_DRAFTS = 5;
const RECEIPT_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export class DraftError extends Error {
  constructor(code, field) { super(code); this.code = code; this.field = field; }
}

const aad = (caseId, schemaVersion, keyId) => Buffer.from(`heard:draft:v1\0${caseId}\0${schemaVersion}\0${keyId}`);

export function encryptAnswers({ key, keyId }, caseId, schemaVersion, answers) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new DraftError('DRAFT_KEY_UNAVAILABLE');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(caseId, schemaVersion, keyId));
  const body = Buffer.concat([cipher.update(JSON.stringify(answers), 'utf8'), cipher.final()]);
  return `v1.${keyId}.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${body.toString('base64url')}`;
}

/** @param {Record<string, Buffer>} keys key ring by ID (current key plus retired keys for reading) */
export function decryptAnswers(keys, caseId, schemaVersion, ciphertext) {
  const parts = typeof ciphertext === 'string' ? ciphertext.split('.') : [];
  if (parts.length !== 5 || parts[0] !== 'v1') throw new DraftError('DRAFT_CIPHERTEXT_INVALID');
  const [, keyId, iv, tag, body] = parts;
  const key = keys[keyId];
  if (!key) throw new DraftError('DRAFT_KEY_UNAVAILABLE');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
    decipher.setAAD(aad(caseId, schemaVersion, keyId));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]).toString('utf8'));
  } catch {
    throw new DraftError('DRAFT_CIPHERTEXT_INVALID');
  }
}

export function newReceiptReference() {
  return `HRD-R-${[...randomBytes(10)].map(b => RECEIPT_ALPHABET[b & 31]).join('')}`;
}

export function isValidIdempotencyKey(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(value);
}

const NEXT_STEPS = 'HEARD has your submission privately. Nothing is published or shared with helpers or partners unless you choose that separately. Save your reference; you will need your recovery code to sign back in.';

/**
 * @param {{pool:any, adapter:any, crypto:{key:Buffer, keyId:string, keyring?:Record<string,Buffer>}, secret:Buffer}} deps
 */
export function createDraftService({ pool, adapter, crypto, secret }) {
  const keyring = { ...(crypto.keyring ?? {}), [crypto.keyId]: crypto.key };

  async function load(client, caseId) {
    const row = (await client.query('SELECT d.schema_version, d.revision, d.ciphertext, d.updated_at, d.expires_at, c.kind, c.status FROM heard_intake_drafts d JOIN heard_cases c ON c.id = d.case_id WHERE d.case_id=$1', [caseId])).rows[0];
    if (!row) throw new DraftError('NOT_FOUND');
    return { caseId, kind: row.kind, status: row.status, revision: row.revision, schemaVersion: row.schema_version, answers: decryptAnswers(keyring, caseId, row.schema_version, row.ciphertext), updatedAt: row.updated_at, expiresAt: row.expires_at };
  }

  return {
    async create(session, { kind }, { now = new Date() } = {}) {
      if (!KINDS.includes(kind)) throw new DraftError('INTAKE_KIND_INVALID', 'kind');
      return withSession(pool, session, async client => {
        const open = (await client.query("SELECT count(*)::int AS n FROM heard_cases WHERE subject_id=$1 AND status='draft'", [session.subjectId])).rows[0].n;
        if (open >= MAX_OPEN_DRAFTS) throw new DraftError('DRAFT_LIMIT_REACHED');
        const caseId = randomUUID();
        await adapter.createDraft(client, { caseId, subjectId: session.subjectId, kind });
        const expiresAt = new Date(now.getTime() + DRAFT_TTL_MS);
        await client.query('INSERT INTO heard_intake_drafts(case_id, schema_version, revision, ciphertext, key_id, expires_at) VALUES($1,$2,0,$3,$4,$5)',
          [caseId, INTAKE_SCHEMA_VERSION, encryptAnswers(crypto, caseId, INTAKE_SCHEMA_VERSION, { kind }), crypto.keyId, expiresAt]);
        return { caseId, kind, revision: 0, expiresAt };
      });
    },

    async get(session, caseId) {
      return withSession(pool, session, async client => {
        await authorizeCase(client, session, session.assurance === 'staff_mfa' ? 'review.read_case' : 'case.read', caseId);
        const draft = await load(client, caseId);
        const receipt = (await client.query('SELECT reference, created_at FROM heard_submission_receipts WHERE case_id=$1', [caseId])).rows[0];
        return { ...draft, receipt: receipt ? { reference: receipt.reference, submittedAt: receipt.created_at } : null };
      });
    },

    /** Replace the answers if `revision` is current; otherwise refuse (no silent overwrite). */
    async save(session, caseId, { revision, answers }, { now = new Date() } = {}) {
      if (!Number.isSafeInteger(revision) || revision < 0) throw new DraftError('DRAFT_REVISION_INVALID', 'revision');
      return withSession(pool, session, async client => {
        const current = await authorizeCase(client, session, 'case.edit_draft', caseId);
        const clean = validateAnswers(answers, { partial: true });
        if (clean.kind !== undefined && clean.kind !== current.kind) throw new DraftError('DRAFT_KIND_IMMUTABLE', 'kind');
        clean.kind = current.kind;
        const result = await client.query(
          'UPDATE heard_intake_drafts SET revision=revision+1, ciphertext=$3, key_id=$4, schema_version=$5, updated_at=$6, expires_at=$7 WHERE case_id=$1 AND revision=$2 RETURNING revision',
          [caseId, revision, encryptAnswers(crypto, caseId, INTAKE_SCHEMA_VERSION, clean), crypto.keyId, INTAKE_SCHEMA_VERSION, now, new Date(now.getTime() + DRAFT_TTL_MS)]);
        if (result.rowCount !== 1) throw new DraftError('DRAFT_REVISION_CONFLICT', 'revision');
        return { caseId, revision: result.rows[0].revision, answers: clean };
      });
    },

    /**
     * Submit exactly once. Requires the reviewed revision, complete valid answers and
     * current private-processing consent. Retrying with the same idempotency key
     * returns the original receipt; anything else after submission is refused.
     */
    async submit(session, caseId, { revision, idempotencyKey }) {
      if (!isValidIdempotencyKey(idempotencyKey)) throw new DraftError('DRAFT_IDEMPOTENCY_KEY_INVALID', 'idempotencyKey');
      const keyHash = createHmac('sha256', secret).update(`heard:idempotency:v1\0${session.subjectId}\0${idempotencyKey}`).digest('hex');
      const replay = async () => withSession(pool, session, async client => {
        await authorizeCase(client, session, 'case.read', caseId);
        const row = (await client.query('SELECT reference, idempotency_key_hash, created_at FROM heard_submission_receipts WHERE case_id=$1', [caseId])).rows[0];
        if (row && row.idempotency_key_hash === keyHash) return { reference: row.reference, submittedAt: row.created_at, status: 'submitted', replayed: true, nextSteps: NEXT_STEPS };
        return null;
      });
      const previous = await replay();
      if (previous) return previous;
      try {
        return await withSession(pool, session, async client => {
          const current = await authorizeCase(client, session, 'case.submit', caseId);
          const draft = await load(client, caseId);
          if (draft.revision !== revision) throw new DraftError('DRAFT_REVISION_CONFLICT', 'revision');
          validateAnswers(draft.answers, { partial: false });
          const consent = await requireConsent(client, caseId, 'private_processing');
          await adapter.submit(client, { caseId, actorId: session.subjectId, policyVersion: consent.policyVersion });
          // Submitted answers leave the draft-expiry path; retention is governed separately (HEARD-41).
          await client.query('UPDATE heard_intake_drafts SET expires_at=NULL WHERE case_id=$1', [caseId]);
          const reference = newReceiptReference();
          const receipt = (await client.query('INSERT INTO heard_submission_receipts(case_id, reference, idempotency_key_hash, schema_version) VALUES($1,$2,$3,$4) RETURNING created_at', [caseId, reference, keyHash, draft.schemaVersion])).rows[0];
          await audit(client, session.subjectId, 'intake.submitted', 'allow', { caseId, metadata: { reason: current.kind } });
          return { reference, submittedAt: receipt.created_at, status: 'submitted', replayed: false, nextSteps: NEXT_STEPS };
        });
      } catch (error) {
        // A concurrent retry with the same key may have won the race.
        if (['ADAPTER_STATE_CONFLICT', 'STATE_FORBIDS_ACTION', 'NOT_FOUND'].includes(error?.code)) {
          const raced = await replay().catch(() => null);
          if (raced) return raced;
        }
        throw error;
      }
    },

    /** Withdraw. For an unsubmitted draft the encrypted answers are deleted immediately. */
    async withdraw(session, caseId) {
      return withSession(pool, session, async client => {
        const current = await authorizeCase(client, session, 'case.withdraw', caseId);
        await adapter.withdraw(client, { caseId, actorId: session.subjectId });
        if (current.status === 'draft') await client.query('DELETE FROM heard_intake_drafts WHERE case_id=$1', [caseId]);
        await audit(client, session.subjectId, 'intake.withdrawn', 'allow', { caseId, metadata: { reason: current.status } });
        return { caseId, status: 'withdrawn', answersDeleted: current.status === 'draft' };
      });
    },

    /** The contributor's own cases with status and receipt reference only (no content). */
    async listMine(session) {
      return withSession(pool, session, async client => (await client.query(
        `SELECT c.id, c.kind, c.status, c.updated_at, r.reference FROM heard_cases c
         LEFT JOIN heard_submission_receipts r ON r.case_id = c.id
         WHERE c.subject_id=$1 ORDER BY c.created_at DESC LIMIT 50`, [session.subjectId])).rows
        .map(r => ({ caseId: r.id, kind: r.kind, status: r.status, updatedAt: r.updated_at, reference: r.reference ?? null })));
    },
  };
}

/** Job: delete expired unsubmitted drafts and withdraw their cases. Runs as heard_job_worker. */
export async function purgeExpiredDrafts(pool) {
  return withScope(pool, { role: 'heard_job_worker', settings: { job_purpose: 'draft_expiry' } }, async client => {
    // RLS limits both statements to drafts that have actually expired.
    const withdrawn = (await client.query("SELECT id FROM heard_cases WHERE status='draft' FOR UPDATE")).rows.map(r => r.id);
    if (!withdrawn.length) return 0;
    await client.query("UPDATE heard_cases SET status='withdrawn', updated_at=now() WHERE id = ANY($1::uuid[]) AND status='draft'", [withdrawn]);
    const deleted = await client.query('DELETE FROM heard_intake_drafts WHERE case_id = ANY($1::uuid[])', [withdrawn]);
    return deleted.rowCount;
  });
}
