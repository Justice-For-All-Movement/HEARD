import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { startPostgres } from '../database/postgres-fixture.mjs';
import { migrate, migrationsDirectory, bindEnvironment, probeDatabase, withScope, LATEST_MIGRATION } from '../../packages/database/src/index.mjs';
import { loadConfig } from '../../packages/config/src/index.mjs';
import { createApp } from '../../packages/server/src/index.mjs';

const token = 'operator-'.padEnd(48, 'z');
const silent = { debug() {}, info() {}, warn() {}, error() {} };

test('database readiness, environment binding and scoped roles on native PostgreSQL', async t => {
  const server = await startPostgres();
  const admin = await server.database('heard_test_ops');
  const pools = [];
  const pool = (user) => { const p = new pg.Pool({ ...server.connection('heard_test_ops', user), max: 3 }); pools.push(p); return p; };
  try {
    const owner = pool();
    await t.test('an empty database is not ready and reports pending migrations', async () => {
      assert.deepEqual(await probeDatabase(owner, { environment: 'ci' }), { status: 'fail', detail: { code: 'MIGRATIONS_PENDING', migrationVersion: 0 } });
    });

    await migrate(admin, migrationsDirectory);

    await t.test('a migrated but unbound database is not ready', async () => {
      assert.equal((await probeDatabase(owner, { environment: 'ci' })).detail.code, 'ENVIRONMENT_UNBOUND');
    });

    await t.test('binding is permanent and a different environment cannot reuse the database', async () => {
      assert.equal(await bindEnvironment(admin, 'ci'), 'ci');
      assert.equal(await bindEnvironment(admin, 'ci'), 'ci');
      await assert.rejects(bindEnvironment(admin, 'production'), { code: 'ENVIRONMENT_MISMATCH' });
      await assert.rejects(admin.query("UPDATE heard_deployment_identity SET environment='production'"), /immutable/);
      await assert.rejects(admin.query('DELETE FROM heard_deployment_identity'), /immutable/);
      assert.deepEqual(await probeDatabase(owner, { environment: 'ci' }), { status: 'ok', detail: { migrationVersion: LATEST_MIGRATION } });
      assert.equal((await probeDatabase(owner, { environment: 'production' })).detail.code, 'ENVIRONMENT_MISMATCH');
    });

    await t.test('a non-superuser login granted heard_api is still bound by forced RLS', async () => {
      await admin.query("CREATE ROLE heard_test_runtime LOGIN NOSUPERUSER NOBYPASSRLS");
      await admin.query('GRANT heard_api TO heard_test_runtime WITH INHERIT FALSE, SET TRUE');
      const runtime = pool('heard_test_runtime');
      await admin.query(await (await import('node:fs/promises')).readFile('db/fixtures/synthetic.sql', 'utf8'));
      const count = await withScope(runtime, { subjectId: '00000000-0000-4000-8000-000000000001' }, c => c.query('SELECT count(*)::int AS n FROM heard_jobs').catch(e => e.code));
      assert.equal(count, '42501', 'heard_api has no job privileges');
      // Without inherited privileges, the login role itself cannot read private tables directly.
      await assert.rejects(runtime.query('SELECT * FROM heard_cases'), { code: '42501' });
      await assert.rejects(withScope(runtime, { role: 'postgres' }, async () => {}), /Unknown scoped role/);
      await assert.rejects(withScope(runtime, { subjectId: 'not-a-uuid' }, async () => {}), /Invalid subject/);
    });

    await t.test('readiness endpoint requires the database once configured and hides detail from the public', async () => {
      const config = loadConfig({ HEARD_ENV: 'ci', DATABASE_URL: 'postgres://fixture@localhost/heard_test_ops', HEARD_OPERATIONS_TOKEN: token });
      const app = createApp({ config, pool: owner, logger: silent });
      const ready = await app.handle(new Request('http://heard.test/api/ready'));
      assert.equal(ready.status, 200);
      assert.deepEqual(await ready.json(), { status: 'ready' });
      const hidden = await app.handle(new Request('http://heard.test/api/ready?detail=1', { headers: { authorization: 'Bearer wrong' } }));
      assert.equal(hidden.status, 404);
      const detail = await app.handle(new Request('http://heard.test/api/ready?detail=1', { headers: { authorization: `Bearer ${token}` } }));
      const body = await detail.json();
      assert.equal(body.components.database.status, 'ok');
      assert.doesNotMatch(JSON.stringify(body), /fixture@localhost|operator-/);

      const wrongEnv = createApp({ config: loadConfig({ HEARD_ENV: 'staging', DATABASE_URL: 'postgres://fixture@localhost/heard_test_ops', HEARD_OPERATIONS_TOKEN: token }), pool: owner, logger: silent });
      const notReady = await wrongEnv.handle(new Request('http://heard.test/api/ready'));
      assert.equal(notReady.status, 503);
      assert.deepEqual(await notReady.json(), { status: 'not_ready' });

      const unreachable = createApp({ config: loadConfig({ HEARD_ENV: 'ci', DATABASE_URL: 'postgres://nobody@127.0.0.1:1/none' }), logger: silent });
      try {
        const down = await unreachable.handle(new Request('http://heard.test/api/ready'));
        assert.equal(down.status, 503);
        const live = await unreachable.handle(new Request('http://heard.test/api/health'));
        assert.equal(live.status, 200, 'liveness does not depend on the database');
      } finally { await unreachable.close(); }
    });
  } finally {
    for (const p of pools) await p.end();
    await admin.end();
    await server.stop();
  }
});
