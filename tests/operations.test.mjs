import test from 'node:test';
import assert from 'node:assert/strict';
import { assessReadiness, createLogger, operatorAuthorized, publicReadiness, redactFields, liveness, errorCode } from '../packages/operations/src/index.mjs';

test('logs keep only allowlisted, token-free fields', () => {
  const lines = [];
  const log = createLogger({ sink: l => lines.push(JSON.parse(l)) });
  log.info('request', { route: '/api/health', statusCode: 200, narrative: 'my private story', email: 'person@example.org', reason: 'person@example.org', code: 'A'.repeat(40) });
  const [line] = lines;
  assert.equal(line.route, '/api/health');
  assert.equal(line.narrative, '[redacted]');
  assert.equal(line.email, '[redacted]');
  assert.equal(line.reason, '[redacted]');
  assert.equal(line.code, '[redacted]');
  assert.doesNotMatch(JSON.stringify(lines), /private story|example\.org/);
  log.debug('hidden');
  assert.equal(lines.length, 1);
  assert.equal(redactFields({ durationMs: 3, applied: [1, 2] }).applied.length, 2);
});

test('errors map to codes, never messages', () => {
  assert.equal(errorCode(Object.assign(new Error('secret detail'), { code: '42P01' })), '42P01');
  assert.equal(errorCode('string with secret'), 'UNKNOWN');
});

test('liveness never claims readiness', () => {
  assert.deepEqual(Object.keys(liveness()), ['status', 'release', 'readiness']);
});

test('readiness requires every required probe, tolerates optional ones and times out', async () => {
  const ok = async () => ({ status: 'ok' });
  const off = async () => ({ status: 'not_configured' });
  assert.equal((await assessReadiness([{ name: 'a', required: true, probe: ok }, { name: 'b', required: false, probe: off }])).ready, true);
  const failing = await assessReadiness([{ name: 'db', required: true, probe: async () => { throw Object.assign(new Error('postgres://user:pw@host'), { code: 'ECONNREFUSED' }); } }]);
  assert.equal(failing.ready, false);
  assert.deepEqual(failing.components.db.detail, { code: 'ECONNREFUSED' });
  assert.doesNotMatch(JSON.stringify(failing), /pw@host/);
  const slow = await assessReadiness([{ name: 'slow', required: true, probe: () => new Promise(() => {}) }], { timeoutMs: 20 });
  assert.equal(slow.components.slow.detail.code, 'PROBE_TIMEOUT');
  assert.deepEqual(publicReadiness(slow), { status: 'not_ready' });
  const bogus = await assessReadiness([{ name: 'x', required: true, probe: async () => ({ status: 'green' }) }]);
  assert.equal(bogus.ready, false);
});

test('operator token comparison denies when unset, malformed or wrong', () => {
  const token = 'x'.repeat(40);
  assert.equal(operatorAuthorized(`Bearer ${token}`, token), true);
  assert.equal(operatorAuthorized(`Bearer ${token}`, null), false);
  assert.equal(operatorAuthorized(token, token), false);
  assert.equal(operatorAuthorized(`Bearer ${'y'.repeat(40)}`, token), false);
  assert.equal(operatorAuthorized(undefined, token), false);
});
