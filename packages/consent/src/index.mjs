/**
 * HEARD-09 privacy choices and versioned consent.
 *
 * Each purpose is decided independently; nothing inherits from another toggle.
 * A grant counts only if it is the latest event for that purpose, was given
 * against the CURRENT policy version and text digest, is unexpired, and its scope
 * covers the specific recipient/asset in question. Absence or staleness denies.
 */
import { createHash } from 'node:crypto';
import { authorizeCase } from '@heard/authorization';
import { audit } from '@heard/identity';

const policy = (fields) => Object.freeze({ ...fields, sha256: createHash('sha256').update(`${fields.version}\n${fields.text}`).digest('hex') });

/** Plain-language policy texts. Changing text requires a new version; old grants then become stale. */
export const CONSENT_POLICIES = Object.freeze({
  private_processing: policy({
    version: '2026-11-15.1',
    title: 'Keep and review what I submit',
    text: 'HEARD will store what you submit in a private database and let assigned HEARD reviewers read it to understand your situation. Our hosting and database providers process it on our behalf. This is confidential managed processing, not end-to-end encryption. Nothing is published, shared with helpers, or sent to partners because of this choice.',
    recipients: ['assigned HEARD reviewers', 'hosting and database providers (processing only)'],
    scopeKeys: [],
  }),
  contact: policy({
    version: '2026-11-15.1',
    title: 'Contact me about this submission',
    text: 'HEARD may contact you through the channel you choose about this submission only. Messages will not include what you wrote. You can withdraw this at any time.',
    recipients: ['assigned HEARD reviewers'],
    scopeKeys: ['channels'],
  }),
  helper_access: policy({
    version: '2026-11-15.1',
    title: 'Share specific items with a helper',
    text: 'Only the helper you name can view only the items you select, until the date you choose. You can revoke this; HEARD cannot recall copies a helper already made.',
    recipients: ['the named helper'],
    scopeKeys: ['recipients', 'assets'],
  }),
  publication: policy({
    version: '2026-11-15.1',
    title: 'Publish a reviewed version',
    text: 'After review, HEARD may publish only the edited fields and files you approve. Original files are never published. Public pages can be copied by others and may persist after withdrawal.',
    recipients: ['the public'],
    scopeKeys: ['assets', 'fields'],
  }),
  identity_display: policy({
    version: '2026-11-15.1',
    title: 'How you appear if anything is published',
    text: 'Choose whether a published account shows a name you choose, a pseudonym, or no name. A pseudonym does not guarantee anonymity: details in your account can still identify you.',
    recipients: ['the public, only if you also agree to publication'],
    scopeKeys: ['mode'],
  }),
  archive_replication: policy({
    version: '2026-11-15.1',
    title: 'Copy published material to independent archives',
    text: 'Published material may be copied to independent archives that HEARD does not control. Those copies may remain even if you later withdraw. This is separate from publication.',
    recipients: ['independent archive operators'],
    scopeKeys: [],
  }),
});
export const PURPOSES = Object.freeze(Object.keys(CONSENT_POLICIES));
const IDENTITY_MODES = ['named', 'pseudonymous', 'private'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class ConsentError extends Error {
  constructor(code, field) { super(code); this.code = code; this.field = field; }
}

/** Validate and canonicalize a scope for a purpose. Unknown keys are refused. */
export function normalizeScope(purpose, scope = {}) {
  const definition = CONSENT_POLICIES[purpose];
  if (!definition) throw new ConsentError('CONSENT_PURPOSE_UNKNOWN');
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) throw new ConsentError('CONSENT_SCOPE_INVALID');
  const out = {};
  for (const [key, value] of Object.entries(scope)) {
    if (!definition.scopeKeys.includes(key)) throw new ConsentError('CONSENT_SCOPE_INVALID', key);
    if (key === 'mode') {
      if (!IDENTITY_MODES.includes(value)) throw new ConsentError('CONSENT_SCOPE_INVALID', key);
      out.mode = value;
    } else if (key === 'channels') {
      if (!Array.isArray(value) || value.some(v => !['in_app'].includes(v))) throw new ConsentError('CONSENT_SCOPE_INVALID', key);
      out.channels = [...new Set(value)].sort();
    } else if (key === 'fields') {
      if (!Array.isArray(value) || value.some(v => typeof v !== 'string' || !/^[a-z][a-z_]{0,40}$/.test(v))) throw new ConsentError('CONSENT_SCOPE_INVALID', key);
      out.fields = [...new Set(value)].sort();
    } else {
      if (!Array.isArray(value) || value.length > 100 || value.some(v => typeof v !== 'string' || !UUID.test(v))) throw new ConsentError('CONSENT_SCOPE_INVALID', key);
      out[key] = [...new Set(value)].sort();
    }
  }
  for (const key of definition.scopeKeys) {
    if (!(key in out)) throw new ConsentError('CONSENT_SCOPE_REQUIRED', key);
    if (Array.isArray(out[key]) && out[key].length === 0) throw new ConsentError('CONSENT_SCOPE_REQUIRED', key);
  }
  return out;
}

/**
 * Effective state per purpose from an ordered event list (by sequence).
 * @returns {Record<string, {status:'granted'|'not_granted'|'revoked'|'stale'|'expired', scope?:object, policyVersion?:string}>}
 */
export function effectiveConsents(events, { now = new Date() } = {}) {
  const latest = new Map();
  for (const event of [...events].sort((a, b) => Number(a.sequence) - Number(b.sequence))) latest.set(event.purpose, event);
  const result = {};
  for (const purpose of PURPOSES) {
    const event = latest.get(purpose);
    const current = CONSENT_POLICIES[purpose];
    if (!event) result[purpose] = { status: 'not_granted' };
    else if (event.decision === 'revoke') result[purpose] = { status: 'revoked', policyVersion: event.policyVersion };
    else if (event.policyVersion !== current.version || event.policyTextSha256 !== current.sha256) result[purpose] = { status: 'stale', policyVersion: event.policyVersion };
    else if (event.expiresAt && event.expiresAt <= now) result[purpose] = { status: 'expired', policyVersion: event.policyVersion };
    else result[purpose] = { status: 'granted', scope: event.scope ?? {}, policyVersion: event.policyVersion };
  }
  return result;
}

/**
 * Whether consent covers an action. Purposes never substitute for each other.
 * @param {{recipientId?:string, assetIds?:string[], fields?:string[]}} target
 */
export function consentCovers(effective, purpose, target = {}) {
  const state = effective[purpose];
  if (!state || state.status !== 'granted') return false;
  const scope = state.scope ?? {};
  if (target.recipientId !== undefined && !(scope.recipients ?? []).includes(target.recipientId)) return false;
  if (target.assetIds !== undefined && (!target.assetIds.length || target.assetIds.some(id => !(scope.assets ?? []).includes(id)))) return false;
  if (target.fields !== undefined && (!target.fields.length || target.fields.some(f => !(scope.fields ?? []).includes(f)))) return false;
  if (purpose === 'publication' && effective.identity_display?.status !== 'granted') return false;
  if (purpose === 'archive_replication' && effective.publication?.status !== 'granted') return false;
  return true;
}

/** Plain-language disclosure preview matching the effective permissions exactly. */
export function disclosurePreview(effective) {
  return PURPOSES.map(purpose => {
    const policy = CONSENT_POLICIES[purpose];
    const state = effective[purpose];
    const active = consentCovers(effective, purpose);
    return {
      purpose,
      title: policy.title,
      status: state.status,
      effective: active,
      recipients: active ? policy.recipients : [],
      scope: active ? state.scope : {},
      summary: active ? `Allowed: ${policy.title.toLowerCase()}.` : state.status === 'stale'
        ? 'Your earlier choice was made under a previous policy and no longer applies. Review the current text to decide again.'
        : state.status === 'granted'
          ? 'Not in effect until the related choice it depends on is also allowed.'
          : 'Not allowed. Nothing happens for this purpose unless you choose it.',
    };
  });
}

/** Load consent events for a case inside an authorized scope. */
export async function loadConsents(client, caseId) {
  const rows = (await client.query('SELECT sequence, purpose, decision, policy_version, policy_text_sha256, scope, expires_at, recorded_at FROM heard_consent_records WHERE case_id=$1 ORDER BY sequence', [caseId])).rows;
  return rows.map(r => ({ sequence: Number(r.sequence), purpose: r.purpose, decision: r.decision, policyVersion: r.policy_version, policyTextSha256: r.policy_text_sha256, scope: r.scope, expiresAt: r.expires_at, recordedAt: r.recorded_at }));
}

export async function caseConsentState(client, session, caseId, { now = new Date() } = {}) {
  await authorizeCase(client, session, 'case.read', caseId, { now });
  const effective = effectiveConsents(await loadConsents(client, caseId), { now });
  return { effective, preview: disclosurePreview(effective) };
}

/**
 * Record a decision. The client must echo the policy version it displayed; a
 * mismatch (stale page) is refused so nobody consents to text they did not see.
 */
export async function recordConsent(client, session, caseId, { purpose, decision, policyVersion, scope = {}, expiresAt = null }, { now = new Date() } = {}) {
  const definition = CONSENT_POLICIES[purpose];
  if (!definition) throw new ConsentError('CONSENT_PURPOSE_UNKNOWN', 'purpose');
  if (!['grant', 'revoke'].includes(decision)) throw new ConsentError('CONSENT_DECISION_INVALID', 'decision');
  if (decision === 'grant' && policyVersion !== definition.version) throw new ConsentError('CONSENT_POLICY_STALE', 'policyVersion');
  const canonical = decision === 'grant' ? normalizeScope(purpose, scope) : {};
  if (expiresAt !== null && (!(expiresAt instanceof Date) || expiresAt <= now)) throw new ConsentError('CONSENT_EXPIRY_INVALID', 'expiresAt');
  await authorizeCase(client, session, 'consent.record', caseId, { now });
  await client.query(
    'INSERT INTO heard_consent_records(case_id, actor_id, purpose, decision, policy_version, policy_text_sha256, scope, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
    [caseId, session.subjectId, purpose, decision, decision === 'grant' ? definition.version : (policyVersion ?? definition.version), decision === 'grant' ? definition.sha256 : null, canonical, expiresAt]);
  await audit(client, session.subjectId, `consent.${decision}`, 'allow', { caseId, metadata: { reason: purpose } });
  return caseConsentState(client, session, caseId, { now });
}

/** Guard used by downstream actions (submission, publication, helper access). */
export async function requireConsent(client, caseId, purpose, target = {}, { now = new Date() } = {}) {
  const effective = effectiveConsents(await loadConsents(client, caseId), { now });
  if (!consentCovers(effective, purpose, target)) throw new ConsentError('CONSENT_REQUIRED', purpose);
  return effective[purpose];
}

/** Public, unauthenticated policy texts for display. */
export function publicPolicies() {
  return PURPOSES.map(purpose => {
    const p = CONSENT_POLICIES[purpose];
    return { purpose, version: p.version, title: p.title, text: p.text, recipients: p.recipients, scopeKeys: p.scopeKeys, sha256: p.sha256 };
  });
}
