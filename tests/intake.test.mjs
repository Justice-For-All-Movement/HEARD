import test from 'node:test';
import assert from 'node:assert/strict';
import { STEPS, FIELDS, validateAnswers, classify, CLASSIFICATIONS, publicSchema } from '../packages/intake/src/index.mjs';

const complete = { kind: 'experience', identity_mode: 'private', narrative: 'A synthetic account of a fictional event for testing.' };

test('every field is classified, labelled and belongs to one step', () => {
  for (const [id, def] of Object.entries(FIELDS)) {
    assert.ok(CLASSIFICATIONS.includes(def.classification), id);
    assert.ok(def.label.length > 5, id);
    assert.equal(STEPS.filter(s => s.fields.some(f => f.id === id)).length, 1, id);
  }
  assert.deepEqual(STEPS.map(s => s.id), ['pathway', 'privacy', 'account', 'context', 'help', 'evidence', 'review']);
  assert.ok(JSON.stringify(publicSchema()).length < 20000);
});

test('no legal name, email, phone or address is ever requested; identifying detail is optional', () => {
  const ids = Object.keys(FIELDS).join(' ');
  assert.doesNotMatch(ids, /email|phone|legal_name|first_name|last_name|address|ssn|birth/);
  for (const def of Object.values(FIELDS).filter(f => f.classification === 'C3')) assert.equal(def.requiredFor.length, 0, def.id);
  assert.deepEqual(validateAnswers(complete), complete);
});

test('full validation requires the pathway, identity choice and narrative', () => {
  assert.throws(() => validateAnswers({}), e => e.errors.kind === 'required');
  assert.throws(() => validateAnswers({ kind: 'question' }), e => e.errors.narrative === 'required' && e.errors.identity_mode === 'required');
  assert.deepEqual(validateAnswers({ kind: 'question' }, { partial: true }), { kind: 'question' });
});

test('values are type-checked, bounded and normalized; unknown fields are rejected', () => {
  assert.throws(() => validateAnswers({ ...complete, email: 'person@example.org' }), e => e.errors.email === 'unknown_field');
  assert.throws(() => validateAnswers({ ...complete, kind: 'publish_now' }), e => e.errors.kind === 'invalid_option');
  assert.throws(() => validateAnswers({ ...complete, narrative: 'x'.repeat(20001) }), e => e.errors.narrative === 'too_long');
  assert.throws(() => validateAnswers({ ...complete, narrative: 'short' }), e => e.errors.narrative === 'too_short');
  assert.throws(() => validateAnswers({ ...complete, narrative: 'bad \u0000 byte in text' }), e => e.errors.narrative === 'characters');
  assert.throws(() => validateAnswers({ ...complete, categories: ['policing', 'housing', 'records', 'benefits', 'other'] }), e => e.errors.categories === 'too_many');
  assert.throws(() => validateAnswers({ ...complete, narrative: { $gt: '' } }), e => e.errors.narrative === 'type');
  assert.equal(validateAnswers({ ...complete, narrative: '  spaced\r\nlines here  ' }).narrative, 'spaced\nlines here');
  assert.equal(validateAnswers({ ...complete, summary: '   ' }).summary, undefined, 'blank optional dropped');
});

test('date and place precision choices are enforced', () => {
  assert.equal(validateAnswers({ ...complete, date_precision: 'month', date: '2026-03' }).date, '2026-03');
  assert.throws(() => validateAnswers({ ...complete, date_precision: 'year', date: '2026-03-04' }), e => e.errors.date === 'precision_mismatch');
  assert.throws(() => validateAnswers({ ...complete, date_precision: 'day', date: '2026-02-30' }), e => e.errors.date === 'invalid_date');
  assert.throws(() => validateAnswers({ ...complete, date: '2999-01-01' }), e => e.errors.date === 'invalid_date');
  assert.throws(() => validateAnswers({ ...complete, location_precision: 'none', location: 'Ohio' }), e => e.errors.location === 'precision_mismatch');
  assert.throws(() => validateAnswers({ ...complete, location: '123 Main Street, Springfield' }), e => e.errors.location === 'too_specific');
});

test('classification map covers stored answers', () => {
  const answers = validateAnswers({ ...complete, location: 'Ohio', location_precision: 'region' });
  assert.deepEqual(classify(answers), { kind: 'C1', identity_mode: 'C1', narrative: 'C2', location: 'C3', location_precision: 'C1' });
});
