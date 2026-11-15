import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptAnswers, decryptAnswers, newReceiptReference, isValidIdempotencyKey } from '../packages/drafts/src/index.mjs';

const key = { key: Buffer.alloc(32, 5), keyId: 'k1' };
const A = '00000000-0000-4000-8000-0000000000a1';
const B = '00000000-0000-4000-8000-0000000000b2';

test('draft answers are encrypted, authenticated and bound to their case, schema and key', () => {
  const answers = { kind: 'experience', narrative: 'synthetic narrative text' };
  const ct = encryptAnswers(key, A, 's1', answers);
  assert.doesNotMatch(ct, /synthetic|narrative/);
  assert.notEqual(ct, encryptAnswers(key, A, 's1', answers), 'random IV');
  assert.deepEqual(decryptAnswers({ k1: key.key }, A, 's1', ct), answers);
  assert.throws(() => decryptAnswers({ k1: key.key }, B, 's1', ct), { code: 'DRAFT_CIPHERTEXT_INVALID' }, 'moved to another case');
  assert.throws(() => decryptAnswers({ k1: key.key }, A, 's2', ct), { code: 'DRAFT_CIPHERTEXT_INVALID' }, 'schema relabel');
  assert.throws(() => decryptAnswers({ k1: Buffer.alloc(32, 6) }, A, 's1', ct), { code: 'DRAFT_CIPHERTEXT_INVALID' });
  assert.throws(() => decryptAnswers({}, A, 's1', ct), { code: 'DRAFT_KEY_UNAVAILABLE' });
  const parts = ct.split('.'); parts[4] = parts[4].slice(0, -2) + (parts[4].endsWith('AA') ? 'BB' : 'AA');
  assert.throws(() => decryptAnswers({ k1: key.key }, A, 's1', parts.join('.')), { code: 'DRAFT_CIPHERTEXT_INVALID' }, 'tampered');
  assert.throws(() => encryptAnswers({ key: Buffer.alloc(16), keyId: 'k1' }, A, 's1', answers), { code: 'DRAFT_KEY_UNAVAILABLE' });
});

test('rotated keys: old ciphertext stays readable through the key ring', () => {
  const old = encryptAnswers({ key: Buffer.alloc(32, 1), keyId: 'k0' }, A, 's1', { kind: 'question' });
  assert.deepEqual(decryptAnswers({ k0: Buffer.alloc(32, 1), k1: key.key }, A, 's1', old), { kind: 'question' });
});

test('receipt references are random and contain no case information; idempotency keys are bounded', () => {
  const refs = new Set(Array.from({ length: 1000 }, newReceiptReference));
  assert.equal(refs.size, 1000);
  for (const ref of refs) assert.match(ref, /^HRD-R-[0-9A-HJKMNP-TV-Z]{10}$/);
  assert.equal(isValidIdempotencyKey('0f8b3c1e-2b9a-4a51-9a7d-1c2f3e4d5a6b'), true);
  for (const bad of ['short', 'x'.repeat(129), 'has spaces in it ok', null]) assert.equal(isValidIdempotencyKey(bad), false);
});
