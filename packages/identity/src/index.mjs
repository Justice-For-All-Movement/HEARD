/**
 * HEARD-07 identity: anonymous principals, one-time recovery codes, server-side
 * sessions, pseudonymous public aliases and staff memberships.
 *
 * Secrets presented by clients (session tokens, recovery codes) are never stored;
 * the database holds HMAC-SHA256 verifiers keyed by HEARD_SESSION_SECRET. Lookups go
 * through RLS policies that expose only the row matching the presented verifier.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { withScope } from '@heard/database';

export const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;
export const STAFF_SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 60 * 1000;

export class IdentityError extends Error {
  constructor(code) { super(code); this.code = code; this.name = 'IdentityError'; }
}

/** Domain-separated keyed verifier for a client-held secret. */
export function verifier(secret, purpose, value) {
  if (!Buffer.isBuffer(secret) || secret.length < 32) throw new IdentityError('IDENTITY_SECRET_MISSING');
  return createHmac('sha256', secret).update(`heard:${purpose}:v1\0`).update(value).digest('hex');
}

export function newSessionToken() {
  return randomBytes(32).toString('base64url');
}
export function isWellFormedSessionToken(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

// Crockford base32 without I, L, O, U.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const GROUPS = 5;
const GROUP_LENGTH = 5;
/** 125-bit recovery code, e.g. HRD-7Q2KD-…; shown once and never stored. */
export function newRecoveryCode() {
  const bytes = randomBytes(GROUPS * GROUP_LENGTH);
  const chars = [...bytes].map(b => ALPHABET[b & 31]).join('');
  const groups = [];
  for (let i = 0; i < GROUPS; i++) groups.push(chars.slice(i * GROUP_LENGTH, (i + 1) * GROUP_LENGTH));
  return `HRD-${groups.join('-')}`;
}
/** Tolerate case, spaces, dashes and common look-alikes; reject anything else. */
export function normalizeRecoveryCode(input) {
  if (typeof input !== 'string' || input.length > 80) return null;
  let s = input.toUpperCase().replace(/[\s-]/g, '');
  if (s.startsWith('HRD')) s = s.slice(3);
  s = s.replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length !== GROUPS * GROUP_LENGTH || [...s].some(c => !ALPHABET.includes(c))) return null;
  return s;
}

const RESERVED = ['admin', 'administrator', 'moderator', 'mod', 'support', 'heard', 'official', 'system', 'staff', 'reviewer', 'editor', 'justiceforall', 'security', 'help', 'root'];
const SKELETON = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a', 'i': 'l', '|': 'l', 'rn': 'm', 'vv': 'w' };
/** Confusable-insensitive comparison key: NFKC, casefold, strip marks/separators, map look-alikes. */
export function aliasKey(name) {
  let s = name.normalize('NFKD').replace(/\p{M}/gu, '').normalize('NFKC').toLowerCase();
  s = s.replace(/[\s._-]+/g, '');
  for (const [from, to] of Object.entries(SKELETON)) s = s.split(from).join(to);
  return s;
}
/**
 * Validate a public pseudonym. A pseudonym is a display choice only: it does not
 * hide network metadata, writing style, voice or other re-identifying details.
 */
export function validatePublicPseudonym(value) {
  if (typeof value !== 'string') throw new IdentityError('ALIAS_INVALID');
  const name = value.normalize('NFKC').trim().replace(/\s+/g, ' ');
  if (name.length < 3 || name.length > 48 || !/^[\p{L}\p{N}][\p{L}\p{N} ._-]*$/u.test(name)) throw new IdentityError('ALIAS_INVALID');
  // Mixed-script names (e.g. Latin + Cyrillic) are a common impersonation vector.
  const scripts = new Set([...name].filter(c => /\p{L}/u.test(c)).map(c => /\p{Script=Latin}/u.test(c) ? 'Latin' : /\p{Script=Cyrillic}/u.test(c) ? 'Cyrillic' : /\p{Script=Greek}/u.test(c) ? 'Greek' : 'Other'));
  if (scripts.size > 1) throw new IdentityError('ALIAS_INVALID');
  const key = aliasKey(name);
  if (key.length < 3 || RESERVED.some(word => key.includes(aliasKey(word)))) throw new IdentityError('ALIAS_RESERVED');
  return { alias: name, key };
}

export const PRIVACY_CHOICE_LABELS = Object.freeze({
  named: 'Show a name you choose',
  pseudonymous: 'Show a pseudonym',
  private: 'Keep my identity hidden from the public',
});

/**
 * Start an anonymous principal: no email or phone. Returns the one-time recovery
 * code and a session token; only verifiers are stored.
 */
export async function startAnonymous(pool, { secret, now = new Date() }) {
  const subjectId = randomUUID();
  const recoveryCode = newRecoveryCode();
  const token = newSessionToken();
  const expiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_MS);
  await withScope(pool, { subjectId }, async client => {
    await client.query("INSERT INTO heard_subjects(id, kind) VALUES($1, 'anonymous')", [subjectId]);
    await client.query('INSERT INTO heard_recovery_credentials(subject_id, verifier) VALUES($1,$2)', [subjectId, verifier(secret, 'recovery', normalizeRecoveryCode(recoveryCode))]);
    await client.query("INSERT INTO heard_sessions(subject_id, token_hash, assurance, expires_at) VALUES($1,$2,'anonymous_recovery',$3)", [subjectId, verifier(secret, 'session', token), expiresAt]);
    await audit(client, subjectId, 'identity.anonymous_start', 'allow');
  });
  return { subjectId, recoveryCode, token, expiresAt };
}

/** Resolve a presented session token to its subject, enforcing absolute, idle and revocation limits. */
export async function resolveSession(pool, token, { secret, now = new Date() }) {
  if (!isWellFormedSessionToken(token)) return null;
  const hash = verifier(secret, 'session', token);
  return withScope(pool, { settings: { session_hash: hash } }, async client => {
    const row = (await client.query('SELECT id, subject_id, assurance, expires_at, last_seen_at, revoked_at, token_hash FROM heard_sessions WHERE token_hash=$1', [hash])).rows[0];
    if (!row || !timingSafeEqual(Buffer.from(row.token_hash), Buffer.from(hash))) return null;
    if (row.revoked_at || row.expires_at <= now || now.getTime() - row.last_seen_at.getTime() > SESSION_IDLE_MS) return null;
    if (now.getTime() - row.last_seen_at.getTime() > TOUCH_INTERVAL_MS) await client.query('UPDATE heard_sessions SET last_seen_at=$2 WHERE id=$1', [row.id, now]);
    return { sessionId: row.id, subjectId: row.subject_id, assurance: row.assurance, expiresAt: row.expires_at };
  }).then(async session => {
    if (!session) return null;
    // Subject rows are visible only under the subject's own scope; locked or deleted principals lose access.
    const active = await withScope(pool, { subjectId: session.subjectId }, c => c.query("SELECT 1 FROM heard_subjects WHERE id=$1 AND account_state='active'", [session.subjectId]));
    return active.rows.length ? session : null;
  });
}

/**
 * Redeem a one-time recovery code. On success the code is consumed, a new code is
 * issued (shown once), a fresh session is created and any session the caller
 * presented is revoked (no session fixation). Unknown, used and revoked codes are
 * indistinguishable.
 */
export async function redeemRecovery(pool, code, { secret, presentedToken = null, now = new Date() }) {
  const normalized = normalizeRecoveryCode(code);
  if (!normalized) throw new IdentityError('INVALID_RECOVERY_CODE');
  const presented = verifier(secret, 'recovery', normalized);
  const found = await withScope(pool, { settings: { recovery_verifier: presented } }, async client => {
    // Consume atomically: concurrent redemptions of the same code cannot both succeed.
    const row = (await client.query('UPDATE heard_recovery_credentials SET used_at=$2 WHERE verifier=$1 AND used_at IS NULL AND revoked_at IS NULL RETURNING subject_id', [presented, now])).rows[0];
    return row?.subject_id ?? null;
  });
  if (!found) throw new IdentityError('INVALID_RECOVERY_CODE');
  const recoveryCode = newRecoveryCode();
  const token = newSessionToken();
  const expiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_MS);
  await withScope(pool, { subjectId: found, settings: isWellFormedSessionToken(presentedToken) ? { session_hash: verifier(secret, 'session', presentedToken) } : {} }, async client => {
    const subject = (await client.query("SELECT account_state FROM heard_subjects WHERE id=$1", [found])).rows[0];
    if (subject?.account_state !== 'active') throw new IdentityError('INVALID_RECOVERY_CODE');
    if (isWellFormedSessionToken(presentedToken)) await client.query('UPDATE heard_sessions SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL', [verifier(secret, 'session', presentedToken), now]);
    await client.query('INSERT INTO heard_recovery_credentials(subject_id, verifier) VALUES($1,$2)', [found, verifier(secret, 'recovery', normalizeRecoveryCode(recoveryCode))]);
    await client.query("INSERT INTO heard_sessions(subject_id, token_hash, assurance, expires_at) VALUES($1,$2,'anonymous_recovery',$3)", [found, verifier(secret, 'session', token), expiresAt]);
    await audit(client, found, 'identity.recovery_redeemed', 'allow');
  });
  return { subjectId: found, recoveryCode, token, expiresAt };
}

/** Replace the active recovery code (e.g. the contributor believes it was exposed). */
export async function rotateRecoveryCode(pool, session, { secret, now = new Date() }) {
  const recoveryCode = newRecoveryCode();
  await withScope(pool, { subjectId: session.subjectId }, async client => {
    await client.query('UPDATE heard_recovery_credentials SET revoked_at=$2 WHERE subject_id=$1 AND revoked_at IS NULL AND used_at IS NULL', [session.subjectId, now]);
    await client.query('INSERT INTO heard_recovery_credentials(subject_id, verifier) VALUES($1,$2)', [session.subjectId, verifier(secret, 'recovery', normalizeRecoveryCode(recoveryCode))]);
    await audit(client, session.subjectId, 'identity.recovery_rotated', 'allow');
  });
  return { recoveryCode };
}

export async function endSession(pool, session, { now = new Date(), allSessions = false } = {}) {
  await withScope(pool, { subjectId: session.subjectId }, async client => {
    if (allSessions) await client.query('UPDATE heard_sessions SET revoked_at=$2 WHERE subject_id=$1 AND revoked_at IS NULL', [session.subjectId, now]);
    else await client.query('UPDATE heard_sessions SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL', [session.sessionId, now]);
    await audit(client, session.subjectId, 'identity.session_ended', 'allow');
  });
}

export async function getProfile(pool, session) {
  return withScope(pool, { subjectId: session.subjectId }, async client => {
    const row = (await client.query('SELECT public_alias, language FROM heard_profiles WHERE subject_id=$1', [session.subjectId])).rows[0];
    return { alias: row?.public_alias ?? null, language: row?.language ?? 'en' };
  });
}

/** Set or clear the public alias and preferred language. Duplicate/confusable aliases are refused. */
export async function setProfile(pool, session, { alias, language = 'en' }) {
  if (typeof language !== 'string' || !/^[a-z]{2,3}(-[A-Z]{2})?$/.test(language)) throw new IdentityError('LANGUAGE_INVALID');
  const checked = alias === null || alias === undefined ? { alias: null, key: null } : validatePublicPseudonym(alias);
  try {
    await withScope(pool, { subjectId: session.subjectId }, client => client.query(
      `INSERT INTO heard_profiles(subject_id, public_alias, alias_key, language) VALUES($1,$2,$3,$4)
       ON CONFLICT (subject_id) DO UPDATE SET public_alias=EXCLUDED.public_alias, alias_key=EXCLUDED.alias_key, language=EXCLUDED.language, updated_at=now()`,
      [session.subjectId, checked.alias, checked.key, language]));
  } catch (error) {
    if (error?.code === '23505') throw new IdentityError('ALIAS_UNAVAILABLE');
    throw error;
  }
  return { alias: checked.alias, language };
}

/** Active staff memberships for the subject. Membership alone never grants case access (see authorization). */
export async function activeStaffRoles(client, subjectId, now = new Date()) {
  const rows = (await client.query('SELECT role FROM heard_staff_memberships WHERE subject_id=$1 AND revoked_at IS NULL AND expires_at > $2', [subjectId, now])).rows;
  return [...new Set(rows.map(r => r.role))];
}

/** Provision a staff membership through the operator role (scripts only, never the public API). */
export async function provisionStaff(pool, { subjectId = randomUUID(), role, purpose, expiresAt, grantedBy = null }) {
  await withScope(pool, { role: 'heard_operator', settings: { operator_purpose: 'staff_provisioning' } }, async client => {
    await client.query("INSERT INTO heard_subjects(id, kind) VALUES($1,'staff') ON CONFLICT (id) DO NOTHING", [subjectId]);
    await client.query('INSERT INTO heard_staff_memberships(subject_id, role, purpose, expires_at, granted_by) VALUES($1,$2,$3,$4,$5)', [subjectId, role, purpose, expiresAt, grantedBy]);
  });
  return subjectId;
}

/** Issue a session for a staff subject. Staff sessions require an MFA-verified assurance level. */
export async function startStaffSession(pool, subjectId, { secret, mfaVerified, now = new Date() }) {
  if (mfaVerified !== true) throw new IdentityError('MFA_REQUIRED');
  const token = newSessionToken();
  const expiresAt = new Date(now.getTime() + STAFF_SESSION_ABSOLUTE_MS);
  await withScope(pool, { subjectId }, async client => {
    if (!(await activeStaffRoles(client, subjectId, now)).length) throw new IdentityError('NOT_STAFF');
    await client.query("INSERT INTO heard_sessions(subject_id, token_hash, assurance, expires_at) VALUES($1,$2,'staff_mfa',$3)", [subjectId, verifier(secret, 'session', token), expiresAt]);
    await audit(client, subjectId, 'identity.staff_session_start', 'allow');
  });
  return { token, expiresAt };
}

/** Append an audit event under the current scope. */
export async function audit(client, actorId, action, outcome, { caseId = null, metadata = {} } = {}) {
  await client.query('INSERT INTO heard_audit_events(actor_id, case_id, action, outcome, metadata) VALUES($1,$2,$3,$4,$5)', [actorId, caseId, action, outcome, metadata]);
}

/**
 * In-process sliding-window limiter keyed by an HMAC of the client key (raw IPs are
 * never retained). Per-instance only; a shared limiter is needed for multi-instance deploys.
 */
export function createRateLimiter({ limit, windowMs, secret, maxKeys = 50_000 }) {
  const hits = new Map();
  return {
    check(rawKey, now = Date.now()) {
      const key = createHmac('sha256', secret ?? Buffer.alloc(32)).update(String(rawKey)).digest('base64url').slice(0, 22);
      const recent = (hits.get(key) ?? []).filter(t => now - t < windowMs);
      if (recent.length >= limit) { hits.set(key, recent); return { allowed: false, retryAfterMs: windowMs - (now - recent[0]) }; }
      recent.push(now);
      hits.delete(key);
      hits.set(key, recent);
      if (hits.size > maxKeys) hits.delete(hits.keys().next().value);
      return { allowed: true, retryAfterMs: 0 };
    },
  };
}
