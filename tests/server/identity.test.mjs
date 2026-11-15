import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startHarness, client, ORIGIN } from './harness.mjs';
import { withScope } from '../../packages/database/src/index.mjs';
import { provisionStaff, startStaffSession, resolveSession, verifier, SESSION_IDLE_MS, SESSION_ABSOLUTE_MS, redeemRecovery, startAnonymous } from '../../packages/identity/src/index.mjs';

test('anonymous identity, recovery and sessions on native PostgreSQL with RLS', async t => {
  const h = await startHarness('heard_test_identity');
  const secret = h.config.secrets.sessionSecret;
  try {
    await t.test('anonymous start needs no email or phone and sets a hardened session cookie', async () => {
      const c = client(h.app);
      const res = await c.request('POST', '/api/v1/anonymous/start', {});
      assert.equal(res.status, 201);
      assert.match(res.body.recoveryCode, /^HRD(-[0-9A-Z]{5}){5}$/);
      assert.match(res.body.notice, /metadata/);
      assert.match(res.setCookie, /^__Host-heard_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=\d+$/);
      const session = await c.request('GET', '/api/v1/session');
      assert.equal(session.status, 200);
      assert.equal(session.body.assurance, 'anonymous_recovery');
      assert.deepEqual(session.body.profile, { alias: null, language: 'en' });
      // Only verifiers are stored: neither the code nor the token appears anywhere.
      const token = c.cookie.split('=')[1];
      const dump = JSON.stringify((await h.admin.query('SELECT * FROM heard_sessions')).rows) + JSON.stringify((await h.admin.query('SELECT * FROM heard_recovery_credentials')).rows);
      assert.ok(!dump.includes(token) && !dump.includes(res.body.recoveryCode.slice(4)));
    });

    await t.test('cross-origin, origin-less and form-encoded mutations are refused', async () => {
      assert.equal((await client(h.app, { origin: 'https://evil.example' }).request('POST', '/api/v1/anonymous/start', {})).status, 403);
      assert.equal((await client(h.app, { origin: null }).request('POST', '/api/v1/anonymous/start', {})).status, 403);
      const form = await h.app.handle(new Request(`${ORIGIN}/api/v1/anonymous/start`, { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' }, body: 'a=1' }));
      assert.equal(form.status, 415);
      const crossSite = await client(h.app).request('POST', '/api/v1/anonymous/start', {}, { 'sec-fetch-site': 'cross-site' });
      assert.equal(crossSite.status, 403);
    });

    await t.test('guessed, malformed and stolen-then-revoked tokens grant nothing', async () => {
      for (const cookie of [`__Host-heard_session=${'A'.repeat(43)}`, `__Host-heard_session=${randomUUID()}`, '__Host-heard_session=../../etc', 'other=1']) {
        const c = client(h.app); c.cookie = cookie;
        const res = await c.request('GET', '/api/v1/session');
        assert.equal(res.status, 401);
        assert.deepEqual(res.body.error.code, 'UNAUTHENTICATED');
      }
      const c = client(h.app);
      await c.request('POST', '/api/v1/anonymous/start', {});
      const stolen = c.cookie;
      assert.equal((await c.request('DELETE', '/api/v1/session')).status, 204);
      const thief = client(h.app); thief.cookie = stolen;
      assert.equal((await thief.request('GET', '/api/v1/session')).status, 401);
    });

    await t.test('recovery codes are one-time, rotate on use and revoke the presented session (no fixation)', async () => {
      const original = client(h.app);
      const start = await original.request('POST', '/api/v1/anonymous/start', {});
      const fixated = original.cookie;
      const resumed = await original.request('POST', '/api/v1/anonymous/redeem', { recoveryCode: start.body.recoveryCode.toLowerCase().replace(/-/g, ' ') });
      assert.equal(resumed.status, 200);
      assert.notEqual(original.cookie, fixated, 'a fresh session token is issued');
      const old = client(h.app); old.cookie = fixated;
      assert.equal((await old.request('GET', '/api/v1/session')).status, 401, 'presented session was revoked');
      const replay = await client(h.app).request('POST', '/api/v1/anonymous/redeem', { recoveryCode: start.body.recoveryCode });
      assert.equal(replay.status, 401, 'used code cannot be replayed');
      assert.deepEqual(replay.body.error.code, 'INVALID_RECOVERY_CODE');
      const next = await client(h.app).request('POST', '/api/v1/anonymous/redeem', { recoveryCode: resumed.body.recoveryCode });
      assert.equal(next.status, 200, 'the newly issued code works once');
    });

    await t.test('concurrent redemption of one code succeeds at most once', async () => {
      const { recoveryCode } = await startAnonymous(h.pool, { secret });
      const results = await Promise.allSettled([1, 2, 3, 4].map(() => redeemRecovery(h.pool, recoveryCode, { secret })));
      assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    });

    await t.test('unknown and malformed codes are indistinguishable and throttled', async () => {
      const attacker = client(h.app, { ip: '198.51.100.77' });
      const bodies = new Set();
      for (let i = 0; i < 10; i++) {
        const res = await attacker.request('POST', '/api/v1/anonymous/redeem', { recoveryCode: i % 2 ? 'HRD-00000-00000-00000-00000-00000' : 'nonsense' });
        assert.equal(res.status, 401);
        bodies.add(JSON.stringify(res.body));
      }
      assert.equal(bodies.size, 1);
      const limited = await attacker.request('POST', '/api/v1/anonymous/redeem', { recoveryCode: 'HRD-00000-00000-00000-00000-00000' });
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers.get('retry-after')) > 0);
      const spoofed = client(h.app, { ip: '10.0.0.1, 198.51.100.77' });
      assert.equal((await spoofed.request('POST', '/api/v1/anonymous/redeem', { recoveryCode: 'x' })).status, 429, 'client-supplied forwarding prefixes do not reset the limit');
    });

    await t.test('idle and absolute session limits are enforced', async () => {
      const { token } = await startAnonymous(h.pool, { secret });
      const later = new Date(Date.now() + SESSION_IDLE_MS + 60_000);
      assert.equal(await resolveSession(h.pool, token, { secret, now: later }), null);
      const fresh = await startAnonymous(h.pool, { secret });
      assert.ok(await resolveSession(h.pool, fresh.token, { secret }));
      assert.equal(await resolveSession(h.pool, fresh.token, { secret, now: new Date(Date.now() + SESSION_ABSOLUTE_MS + 1000) }), null);
    });

    await t.test('pseudonyms: reserved, confusable, mixed-script and duplicate aliases are refused', async () => {
      const a = client(h.app); await a.request('POST', '/api/v1/anonymous/start', {});
      const b = client(h.app); await b.request('POST', '/api/v1/anonymous/start', {});
      assert.equal((await a.request('PUT', '/api/v1/profile', { alias: 'River Lantern', language: 'es' })).status, 200);
      assert.deepEqual((await a.request('GET', '/api/v1/session')).body.profile, { alias: 'River Lantern', language: 'es' });
      const dup = await b.request('PUT', '/api/v1/profile', { alias: 'river.lantern' });
      assert.equal(dup.status, 400); assert.equal(dup.body.error.fields.alias, 'ALIAS_UNAVAILABLE');
      for (const alias of ['Adm1n Team', 'HEARD Support', 'Rivеr Lantern' /* Cyrillic e */, 'x', '<script>']) {
        assert.equal((await b.request('PUT', '/api/v1/profile', { alias })).status, 400, alias);
      }
      assert.equal((await b.request('PUT', '/api/v1/profile', { alias: 'Quiet Harbor', email: 'person@example.org' })).status, 400, 'unknown fields rejected');
      assert.equal((await a.request('PUT', '/api/v1/profile', { alias: null })).status, 200, 'alias can be cleared');
    });

    await t.test('RLS: subjects see only their own rows; token lookup exposes one row; ownership columns are immutable', async () => {
      const one = await startAnonymous(h.pool, { secret });
      const two = await startAnonymous(h.pool, { secret });
      const seen = await withScope(h.pool, { subjectId: one.subjectId }, c => c.query('SELECT subject_id FROM heard_sessions UNION ALL SELECT subject_id FROM heard_recovery_credentials UNION ALL SELECT id FROM heard_subjects'));
      assert.ok(seen.rows.length >= 3 && seen.rows.every(r => r.subject_id === one.subjectId));
      const anonymousScope = await withScope(h.pool, {}, c => c.query('SELECT count(*)::int AS n FROM heard_sessions'));
      assert.equal(anonymousScope.rows[0].n, 0, 'no subject and no token: nothing visible');
      const byToken = await withScope(h.pool, { settings: { session_hash: verifier(secret, 'session', two.token) } }, c => c.query('SELECT subject_id FROM heard_sessions'));
      assert.deepEqual(byToken.rows.map(r => r.subject_id), [two.subjectId]);
      await assert.rejects(withScope(h.pool, { settings: { session_hash: verifier(secret, 'session', two.token) } }, c => c.query('UPDATE heard_sessions SET subject_id=$1', [one.subjectId])), { code: '42501' });
      await assert.rejects(withScope(h.pool, { subjectId: one.subjectId }, c => c.query("INSERT INTO heard_sessions(subject_id, token_hash, assurance, expires_at) VALUES($1, repeat('a',64), 'staff_mfa', now()+interval '1 hour')", [two.subjectId])), { code: '42501' });
      await assert.rejects(withScope(h.pool, { subjectId: one.subjectId }, c => c.query("INSERT INTO heard_audit_events(actor_id, action, outcome) VALUES($1,'forged','allow')", [two.subjectId])), { code: '42501' });
      await assert.rejects(h.pool.query('SELECT * FROM heard_sessions'), { code: '42501' }, 'login role has no direct privileges');
    });

    await t.test('staff sessions require provisioning through the operator role and MFA assurance', async () => {
      const staff = await provisionStaff(h.pool, { role: 'reviewer', purpose: 'synthetic review queue', expiresAt: new Date(Date.now() + 86_400_000) });
      await assert.rejects(startStaffSession(h.pool, staff, { secret, mfaVerified: false }), { code: 'MFA_REQUIRED' });
      const { token } = await startStaffSession(h.pool, staff, { secret, mfaVerified: true });
      assert.equal((await resolveSession(h.pool, token, { secret })).assurance, 'staff_mfa');
      const { subjectId } = await startAnonymous(h.pool, { secret });
      await assert.rejects(startStaffSession(h.pool, subjectId, { secret, mfaVerified: true }), { code: 'NOT_STAFF' });
      await assert.rejects(withScope(h.pool, { subjectId }, c => c.query("INSERT INTO heard_staff_memberships(subject_id, role, purpose, expires_at) VALUES($1,'administrator','self-grant', now()+interval '1 day')", [subjectId])), { code: '42501' }, 'API role cannot self-grant staff roles');
      await assert.rejects(withScope(h.pool, { role: 'heard_operator' }, c => c.query("INSERT INTO heard_staff_memberships(subject_id, role, purpose, expires_at) VALUES($1,'administrator','no purpose set', now()+interval '1 day')", [subjectId])), { code: '42501' }, 'operator writes require a declared purpose');
    });

    await t.test('locked principals lose access immediately', async () => {
      const { subjectId, token } = await startAnonymous(h.pool, { secret });
      await withScope(h.pool, { subjectId }, c => c.query("UPDATE heard_subjects SET account_state='locked' WHERE id=$1", [subjectId]));
      assert.equal(await resolveSession(h.pool, token, { secret }), null);
    });
  } finally {
    await h.stop();
  }
});

test('identity routes do not exist while intake is disabled', async () => {
  const h = await startHarness('heard_test_identityoff', { HEARD_INTAKE_ENABLED: 'false' });
  try {
    const res = await client(h.app).request('POST', '/api/v1/anonymous/start', {});
    assert.equal(res.status, 404);
    assert.equal((await client(h.app).request('GET', '/api/v1/session')).status, 404);
  } finally { await h.stop(); }
});
