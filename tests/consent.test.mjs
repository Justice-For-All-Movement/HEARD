import test from 'node:test';
import assert from 'node:assert/strict';
import { CONSENT_POLICIES, PURPOSES, effectiveConsents, consentCovers, disclosurePreview, normalizeScope } from '../packages/consent/src/index.mjs';

const U1 = '00000000-0000-4000-8000-0000000000a1';
const U2 = '00000000-0000-4000-8000-0000000000a2';
let seq = 0;
const grant = (purpose, scope = {}, extra = {}) => ({ sequence: ++seq, purpose, decision: 'grant', policyVersion: CONSENT_POLICIES[purpose].version, policyTextSha256: CONSENT_POLICIES[purpose].sha256, scope, ...extra });
const revoke = purpose => ({ sequence: ++seq, purpose, decision: 'revoke', policyVersion: CONSENT_POLICIES[purpose].version, policyTextSha256: null });

test('absence denies every purpose; purposes never inherit from each other', () => {
  const none = effectiveConsents([]);
  for (const p of PURPOSES) { assert.equal(none[p].status, 'not_granted'); assert.equal(consentCovers(none, p), false); }
  const processing = effectiveConsents([grant('private_processing')]);
  for (const p of PURPOSES.filter(x => x !== 'private_processing')) assert.equal(consentCovers(processing, p), false, p);
});

test('latest event wins by sequence, not by timestamp or array order', () => {
  const a = grant('contact', { channels: ['in_app'] }); const b = revoke('contact');
  assert.equal(effectiveConsents([b, a]).contact.status, 'revoked');
  const c = grant('contact', { channels: ['in_app'] });
  assert.equal(effectiveConsents([c, b, a]).contact.status, 'granted');
});

test('stale policy version or text digest and expiry block consent', () => {
  assert.equal(effectiveConsents([grant('private_processing', {}, { policyVersion: '2020-01-01.1' })]).private_processing.status, 'stale');
  assert.equal(effectiveConsents([grant('private_processing', {}, { policyTextSha256: 'f'.repeat(64) })]).private_processing.status, 'stale');
  const now = new Date('2026-11-15T00:00:00Z');
  assert.equal(effectiveConsents([grant('private_processing', {}, { expiresAt: new Date('2026-11-14T00:00:00Z') })], { now }).private_processing.status, 'expired');
});

test('helper and publication consent cover only listed recipients, assets and fields', () => {
  const eff = effectiveConsents([grant('helper_access', { recipients: [U1], assets: [U2] })]);
  assert.equal(consentCovers(eff, 'helper_access', { recipientId: U1, assetIds: [U2] }), true);
  assert.equal(consentCovers(eff, 'helper_access', { recipientId: U2, assetIds: [U2] }), false);
  assert.equal(consentCovers(eff, 'helper_access', { recipientId: U1, assetIds: [U2, U1] }), false, 'new asset is not covered');
  assert.equal(consentCovers(eff, 'helper_access', { recipientId: U1, assetIds: [] }), false);
  const pub = effectiveConsents([grant('publication', { assets: [U1], fields: ['summary'] })]);
  assert.equal(consentCovers(pub, 'publication', { assetIds: [U1] }), false, 'publication also requires an identity display choice');
  const both = effectiveConsents([grant('publication', { assets: [U1], fields: ['summary'] }), grant('identity_display', { mode: 'private' })]);
  assert.equal(consentCovers(both, 'publication', { assetIds: [U1], fields: ['summary'] }), true);
  assert.equal(consentCovers(both, 'publication', { fields: ['narrative'] }), false);
  assert.equal(consentCovers(both, 'archive_replication'), false, 'replication is separate from publication');
});

test('scopes are validated strictly', () => {
  assert.throws(() => normalizeScope('helper_access', { recipients: [U1] }), { code: 'CONSENT_SCOPE_REQUIRED' });
  assert.throws(() => normalizeScope('helper_access', { recipients: ['everyone'], assets: [U1] }), { code: 'CONSENT_SCOPE_INVALID' });
  assert.throws(() => normalizeScope('private_processing', { recipients: [U1] }), { code: 'CONSENT_SCOPE_INVALID' });
  assert.throws(() => normalizeScope('identity_display', { mode: 'famous' }), { code: 'CONSENT_SCOPE_INVALID' });
  assert.throws(() => normalizeScope('contact', { channels: ['sms'] }), { code: 'CONSENT_SCOPE_INVALID' });
  assert.deepEqual(normalizeScope('helper_access', { recipients: [U2, U1, U1], assets: [U1] }), { recipients: [U1, U2], assets: [U1] });
});

test('preview text matches effective permissions and makes no anonymity or E2EE promise', () => {
  const eff = effectiveConsents([grant('publication', { assets: [U1], fields: ['summary'] })]);
  const preview = disclosurePreview(eff);
  const pub = preview.find(p => p.purpose === 'publication');
  assert.equal(pub.effective, false);
  assert.deepEqual(pub.recipients, []);
  assert.match(pub.summary, /Not in effect/);
  for (const policy of Object.values(CONSENT_POLICIES)) {
    assert.doesNotMatch(policy.text, /(?<!not )guarantee(d|s)? (anonymity|privacy)|(?<!not )end-to-end encrypted/i);
    assert.match(policy.sha256, /^[a-f0-9]{64}$/);
  }
  assert.match(CONSENT_POLICIES.private_processing.text, /not end-to-end encryption/);
  assert.match(CONSENT_POLICIES.archive_replication.text, /may remain/);
});
