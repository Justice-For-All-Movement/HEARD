import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { startWebServer, startExpectingFailure } from './server-fixture.mjs';

const copy = JSON.parse(readFileSync('content/site-copy.json', 'utf8'));
const routes = ['/', ...copy.home.cards.map(x => x.href), '/about', '/privacy', '/editorial-standards', '/contact'];

test('production server: public pages, operations endpoints and fail-closed startup', async t => {
  const server = await startWebServer();
  const pages = new Map();
  try {
    for (const path of routes) {
      const response = await server.fetch(path);
      assert.equal(response.status, 200, `${path} status`);
      pages.set(path, await response.text());
      assert.match(response.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
      assert.equal(response.headers.get('x-powered-by'), null);
    }

    await t.test('six independent canonical journeys render on the home page', () => {
      const home = pages.get('/');
      for (const card of copy.home.cards) {
        assert.ok(home.includes(card.title), `missing pathway ${card.id}`);
        assert.match(home, new RegExp(`href="${card.href}/?"`));
      }
    });

    await t.test('every navigation and footer destination resolves on the server', async () => {
      const seen = new Set();
      for (const [path, html] of pages) {
        for (const match of html.matchAll(/<a\b[^>]*href="([^"]+)"/g)) {
          const href = match[1];
          if (href.startsWith('#') || seen.has(href)) continue;
          assert.ok(href.startsWith('/') && !href.startsWith('//'), `unexpected external link ${href} on ${path}`);
          seen.add(href);
          assert.equal((await server.fetch(href)).status, 200, `broken ${href} on ${path}`);
        }
      }
    });

    await t.test('public shell has landmarks, a skip link, one heading and no collection controls by default', () => {
      for (const [path, html] of pages) {
        assert.match(html, /<html[^>]*lang="en"/);
        assert.match(html, /href="#main"/);
        assert.match(html, /<main[^>]*id="main"/);
        assert.equal([...html.matchAll(/<h1\b/g)].length, 1, `${path}: heading structure`);
        assert.doesNotMatch(html, /<(?:form|input|textarea|select|iframe)\b/i, `${path}: intake is disabled by default`);
        assert.match(html, /Engineering preview:/);
        assert.match(html, /Do not share personal or sensitive information/);
        assert.match(html, /name="robots" content="noindex, nofollow"/);
      }
    });

    await t.test('availability and privacy limits are visible', () => {
      for (const path of routes.filter(x => x !== '/')) assert.match(pages.get(path), /This service is being built/);
      assert.match(pages.get('/privacy'), /No submission protection, anonymity or end-to-end encryption is claimed/);
      assert.match(pages.get('/rights'), /Jurisdiction-specific guides, sources and review dates are not available/);
    });

    await t.test('unknown pages and API routes return 404 without detail', async () => {
      const page = await server.fetch('/definitely-not-a-route');
      assert.equal(page.status, 404);
      assert.match(await page.text(), /Page not found/);
      const api = await server.fetch('/api/v1/unknown');
      assert.equal(api.status, 404);
      assert.deepEqual(await api.json(), { error: { code: 'NOT_FOUND', message: 'Not found.' } });
    });

    await t.test('liveness is separate from readiness and neither leaks configuration', async () => {
      const health = await server.fetch('/api/health');
      assert.equal(health.status, 200);
      assert.equal(health.headers.get('cache-control'), 'no-store');
      assert.deepEqual(Object.keys(await health.json()).sort(), ['readiness', 'release', 'status']);
      const ready = await server.fetch('/api/ready');
      assert.equal(ready.status, 200, 'public shell without a database is ready');
      assert.deepEqual(await ready.json(), { status: 'ready' });
      const detail = await server.fetch('/api/ready?detail=1');
      assert.equal(detail.status, 404, 'detail requires an operator token');
    });

    await t.test('the wizard page does not exist while the feature flag is off', async () => {
      assert.equal((await server.fetch('/share/start')).status, 404);
      assert.doesNotMatch(pages.get('/share'), /share\/start/);
    });

    await t.test('intake API is not reachable while the feature flag is off', async () => {
      const response = await server.fetch('/api/v1/anonymous/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      assert.equal(response.status, 404);
    });
  } finally {
    await server.stop();
  }
});

test('start script refuses unsafe configuration before listening', async () => {
  const intakeWithoutSecrets = await startExpectingFailure({ HEARD_INTAKE_ENABLED: 'true' });
  assert.equal(intakeWithoutSecrets.code, 78);
  assert.match(intakeWithoutSecrets.output, /HEARD_INTAKE_ENABLED requires DATABASE_URL/);
  const productionMemory = await startExpectingFailure({ HEARD_ENV: 'production', HEARD_OBJECT_STORAGE_DRIVER: 'memory' });
  assert.equal(productionMemory.code, 78);
  const secretValue = ['postgres://user', 'do-not-print@db.example.invalid/heard'].join(':');
  const badDatabase = await startExpectingFailure({ HEARD_ENV: 'production', DATABASE_URL: secretValue });
  assert.equal(badDatabase.code, 78);
  assert.match(badDatabase.output, /sslmode=require/);
  assert.doesNotMatch(badDatabase.output, /do-not-print/);
});

test('with the intake flag on, the share page links to an accessible private wizard', async () => {
  const key = n => Buffer.alloc(32, n).toString('base64');
  const server = await startWebServer({
    HEARD_INTAKE_ENABLED: 'true',
    DATABASE_URL: 'postgres://unused@127.0.0.1:1/unused',
    HEARD_SESSION_SECRET: key(1),
    HEARD_DATA_ENCRYPTION_KEY: key(2),
  });
  try {
    const share = await (await server.fetch('/share')).text();
    assert.match(share, /href="\/share\/start"/);
    assert.match(share, /use only fictional information/);
    const response = await server.fetch('/share/start');
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.equal([...html.matchAll(/<h1\b/g)].length, 1);
    assert.match(html, /<h2[^>]*tabindex="-1"[^>]*>How this works<\/h2>/);
    assert.match(html, /You do not need an email address or phone number/);
    assert.match(html, /Hosting and network providers can still see connection details/);
    assert.match(html, /HEARD is not an emergency service/);
    assert.match(html, /<button[^>]*type="button"[^>]*>Begin privately<\/button>/);
    assert.match(html, /Resume with a recovery code/);
    assert.doesNotMatch(html, /(?<!not )end-to-end encrypt|guaranteed anonym/i);
    for (const match of html.matchAll(/<input\b[^>]*>/g)) {
      const id = /id="([^"]+)"/.exec(match[0])?.[1];
      assert.ok(id && html.includes(`for="${id}"`), `unlabelled input ${match[0]}`);
    }
    assert.equal(response.headers.get('cache-control')?.includes('no-store') || response.headers.get('cache-control')?.includes('private') || response.headers.get('cache-control')?.includes('no-cache'), true);
    const schema = await server.fetch('/api/v1/intake/schema');
    assert.equal(schema.status, 200);
  } finally {
    await server.stop();
  }
});
