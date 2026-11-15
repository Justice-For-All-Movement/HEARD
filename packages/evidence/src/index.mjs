/**
 * HEARD-14 evidence integrity, provenance and chain of handling.
 *
 * Originals are immutable in the database (trigger) and identified by SHA-256.
 * Every handling step appends an event to a per-object hash chain computed by the
 * database itself; the ledger head is stored on the object. Verification recomputes
 * every event hash, checks the links and the head, and can re-read the bytes.
 * Ledger entries describe what HEARD did with a file; they never assert that the
 * content is authentic or true. Event detail is restricted to short allowlisted
 * values, so narratives and identities never enter digests or exports.
 */
import { authorizeCase, authorizeObject } from '@heard/authorization';
import { audit } from '@heard/identity';
import { digestObject } from '@heard/storage';

export const OPERATIONS = Object.freeze(['received', 'scan_cleared', 'scan_rejected', 'downloaded', 'verified', 'verification_failed', 'source_asserted', 'manifest_exported']);
export const SOURCES = Object.freeze(['self_recorded', 'recorded_by_someone_else', 'official_record', 'public_source', 'unknown']);
const DETAIL_KEYS = Object.freeze({ reason: /^[a-z_]{1,40}$/, engine: /^[A-Za-z0-9_./ -]{1,80}$/, source: new RegExp(`^(${SOURCES.join('|')})$`), captured: /^\d{4}(-\d{2}(-\d{2})?)?$/ });

export class EvidenceError extends Error {
  constructor(code, field) { super(code); this.code = code; this.field = field; }
}

export function sanitizeDetail(detail = {}) {
  if (!detail || typeof detail !== 'object' || Array.isArray(detail)) throw new EvidenceError('EVIDENCE_DETAIL_INVALID');
  const out = {};
  for (const [key, value] of Object.entries(detail)) {
    if (!DETAIL_KEYS[key] || typeof value !== 'string' || !DETAIL_KEYS[key].test(value)) throw new EvidenceError('EVIDENCE_DETAIL_INVALID', key);
    out[key] = value;
  }
  return out;
}

/** Which kind of actor a verified session is relative to a case. */
export function actorKind(session, caseOwnerId) {
  if (session.subjectId === caseOwnerId) return 'contributor';
  if (session.assurance === 'staff_mfa') return 'staff';
  return 'helper';
}

/** Append one event inside an existing scoped transaction. The database computes order and hashes. */
export async function recordEvent(client, { objectId, caseId, operation, actorKind: kind, actorId = null, detail = {} }) {
  if (!OPERATIONS.includes(operation)) throw new EvidenceError('EVIDENCE_OPERATION_INVALID');
  await client.query('INSERT INTO heard_evidence_events(object_id, case_id, operation, actor_kind, actor_id, detail) VALUES($1,$2,$3,$4,$5,$6)',
    [objectId, caseId, operation, kind, kind === 'service' ? null : actorId, sanitizeDetail(detail)]);
}

/**
 * Verify an object's ledger: every stored hash must equal its recomputation, each
 * event must link to its predecessor, ordinals must be contiguous and the last hash
 * must equal the object's ledger head.
 */
export async function verifyLedger(client, objectId) {
  const object = (await client.query('SELECT ledger_head, ledger_length FROM heard_private_objects WHERE id=$1', [objectId])).rows[0];
  if (!object) throw new EvidenceError('NOT_FOUND');
  const events = (await client.query(
    `SELECT ordinal, operation, actor_kind, detail, recorded_at, prev_hash, event_hash,
       heard_evidence_event_hash(prev_hash, object_id, case_id, ordinal, operation, actor_kind, actor_id, detail, recorded_at) AS recomputed
     FROM heard_evidence_events WHERE object_id=$1 ORDER BY ordinal`, [objectId])).rows;
  let previous = null;
  const problems = [];
  events.forEach((e, index) => {
    if (e.ordinal !== index + 1) problems.push(`gap_at_${index + 1}`);
    if (e.prev_hash !== previous) problems.push(`broken_link_at_${e.ordinal}`);
    if (e.recomputed !== e.event_hash) problems.push(`altered_event_${e.ordinal}`);
    previous = e.event_hash;
  });
  if (previous !== object.ledger_head || events.length !== object.ledger_length) problems.push('head_mismatch');
  return { valid: problems.length === 0, problems, length: events.length, head: object.ledger_head, events };
}

/** Re-read the stored bytes and compare with the recorded digest; record the outcome. */
export async function verifyObjectBytes(client, session, storage, objectId, { now = new Date() } = {}) {
  await authorizeObject(client, session, 'evidence.read', objectId, { now });
  const object = (await client.query('SELECT o.id, o.case_id, o.storage_ref, o.checksum_sha256, o.size_bytes, c.subject_id FROM heard_private_objects o LEFT JOIN heard_cases c ON c.id=o.case_id WHERE o.id=$1', [objectId])).rows[0];
  let matches = false;
  try {
    const actual = await digestObject(storage, object.storage_ref, { maxBytes: Number(object.size_bytes) });
    matches = actual.sha256 === object.checksum_sha256 && actual.size === Number(object.size_bytes);
  } catch { matches = false; }
  await recordEvent(client, { objectId, caseId: object.case_id, operation: matches ? 'verified' : 'verification_failed', actorKind: actorKind(session, object.subject_id), actorId: session.subjectId });
  return { objectId, matches, sha256: object.checksum_sha256 };
}

/** The contributor's own statement about where a file came from. Recorded as a claim, never as verification. */
export async function assertSource(client, session, objectId, { source, captured }, { now = new Date() } = {}) {
  if (!SOURCES.includes(source)) throw new EvidenceError('EVIDENCE_SOURCE_INVALID', 'source');
  const object = await authorizeObject(client, session, 'evidence.read', objectId, { now });
  const owner = await authorizeCase(client, session, 'case.read', object.caseId, { now });
  if (owner.ownerId !== session.subjectId) throw new EvidenceError('NOT_FOUND');
  await recordEvent(client, { objectId, caseId: object.caseId, operation: 'source_asserted', actorKind: 'contributor', actorId: session.subjectId, detail: captured ? { source, captured } : { source } });
  return { objectId, source, captured: captured ?? null };
}

export const MANIFEST_NOTICE = 'This manifest records how HEARD received, checked and handled each file and the SHA-256 digest of the original bytes. It does not establish that any file is authentic, complete or true. Source statements are the contributor\'s own.';

/** Private export manifest for one case (owner or assigned staff). No storage keys, narratives or identities. */
export async function caseManifest(client, session, caseId, { now = new Date() } = {}) {
  await authorizeCase(client, session, session.assurance === 'staff_mfa' ? 'review.read_case' : 'case.read', caseId, { now });
  const objects = (await client.query('SELECT id, declared_type, detected_type, size_bytes, checksum_sha256, quarantine_state, created_at FROM heard_private_objects WHERE case_id=$1 ORDER BY created_at, id', [caseId])).rows;
  const entries = [];
  for (const o of objects) {
    const ledger = await verifyLedger(client, o.id);
    const source = [...ledger.events].reverse().find(e => e.operation === 'source_asserted')?.detail ?? null;
    entries.push({
      objectId: o.id,
      sha256: o.checksum_sha256,
      size: Number(o.size_bytes),
      declaredType: o.declared_type,
      detectedType: o.detected_type,
      state: o.quarantine_state,
      receivedAt: o.created_at,
      contributorSourceStatement: source,
      ledger: { valid: ledger.valid, problems: ledger.problems, length: ledger.length, head: ledger.head, events: ledger.events.map(e => ({ ordinal: e.ordinal, operation: e.operation, actorKind: e.actor_kind, recordedAt: e.recorded_at, detail: e.detail, hash: e.event_hash })) },
    });
  }
  await audit(client, session.subjectId, 'evidence.manifest_exported', 'allow', { caseId, metadata: { reason: 'export' } });
  return { schema: 'heard.evidence-manifest.v1', caseId, generatedAt: now.toISOString(), notice: MANIFEST_NOTICE, hashAlgorithm: 'SHA-256', ledgerFormat: 'heard-ledger-v1', objects: entries };
}
