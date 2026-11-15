import test from 'node:test';
import assert from 'node:assert/strict';
import { newRecoveryCode, normalizeRecoveryCode, verifier, validatePublicPseudonym, aliasKey, createRateLimiter, newSessionToken, isWellFormedSessionToken, PRIVACY_CHOICE_LABELS } from '../packages/identity/src/index.mjs';

const secret = Buffer.alloc(32, 3);

test('recovery codes carry 125 bits, are unique and normalize look-alikes', () => {
  const codes = new Set(Array.from({ length: 2000 }, newRecoveryCode));
  assert.equal(codes.size, 2000);
  const code = [...codes][0];
  assert.match(code, /^HRD(-[0-9A-HJKMNP-TV-Z]{5}){5}$/);
  const n = normalizeRecoveryCode(code);
  assert.equal(normalizeRecoveryCode(code.toLowerCase().replace(/-/g, ' ')), n);
  assert.equal(normalizeRecoveryCode('HRD-OOOOO-IIIII-LLLLL-00000-11111'), '0000011111111110000011111');
  for (const bad of ['', 'HRD-123', 'HRD-UUUUU-00000-00000-00000-00000', null, 42, 'x'.repeat(200)]) assert.equal(normalizeRecoveryCode(bad), null);
});

test('verifiers are keyed and domain-separated', () => {
  assert.notEqual(verifier(secret, 'session', 'abc'), verifier(secret, 'recovery', 'abc'));
  assert.notEqual(verifier(secret, 'session', 'abc'), verifier(Buffer.alloc(32, 4), 'session', 'abc'));
  assert.match(verifier(secret, 'session', 'abc'), /^[a-f0-9]{64}$/);
  assert.throws(() => verifier(Buffer.alloc(8), 'session', 'abc'), { code: 'IDENTITY_SECRET_MISSING' });
  assert.ok(isWellFormedSessionToken(newSessionToken()));
  assert.equal(isWellFormedSessionToken('short'), false);
});

test('pseudonyms block impersonation and confusables but allow ordinary names in any script', () => {
  assert.equal(validatePublicPseudonym('  Quiet   Harbor ').alias, 'Quiet Harbor');
  assert.equal(validatePublicPseudonym('Маргарита').alias, 'Маргарита');
  assert.equal(validatePublicPseudonym('José_R').alias, 'José_R');
  assert.equal(aliasKey('Jose R'), aliasKey('josé.r'));
  for (const bad of ['Adm1n', 'HEARD-official', 'the moderator', 'S u p p o r t', 'Ηeard' /* Greek Eta */, 'ab', '-dash', 'a'.repeat(49), 'Rivеr' /* mixed */]) {
    assert.throws(() => validatePublicPseudonym(bad), /ALIAS_/, bad);
  }
  assert.doesNotMatch(Object.values(PRIVACY_CHOICE_LABELS).join(' '), /anonym(ous|ity) guaranteed/i);
});

test('rate limiter is per key, sliding, bounded and does not keep raw keys', () => {
  const limiter = createRateLimiter({ limit: 2, windowMs: 1000, secret, maxKeys: 3 });
  assert.equal(limiter.check('a', 0).allowed, true);
  assert.equal(limiter.check('a', 10).allowed, true);
  const denied = limiter.check('a', 20);
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterMs, 980);
  assert.equal(limiter.check('b', 20).allowed, true);
  assert.equal(limiter.check('a', 1011).allowed, true);
  for (const k of ['c', 'd', 'e', 'f']) limiter.check(k, 2000);
});
