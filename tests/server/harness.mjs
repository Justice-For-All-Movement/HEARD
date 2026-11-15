import pg from 'pg';
import { startPostgres } from '../database/postgres-fixture.mjs';
import { migrate, migrationsDirectory, bindEnvironment } from '../../packages/database/src/index.mjs';
import { loadConfig } from '../../packages/config/src/index.mjs';
import { createHeardServer } from '../../packages/server/src/index.mjs';

export const ORIGIN = 'http://heard.test';
export const silent = { debug() {}, info() {}, warn() {}, error() {} };
const key = n => Buffer.alloc(32, n).toString('base64');
export const INTAKE_ENV = { HEARD_ENV: 'ci', DATABASE_URL: 'postgres://fixture@localhost/fixture', HEARD_INTAKE_ENABLED: 'true', HEARD_SESSION_SECRET: key(7), HEARD_DATA_ENCRYPTION_KEY: key(9) };

/**
 * Migrated native PostgreSQL database plus an application pool that connects as a
 * NON-superuser login role (like a managed-provider owner), so RLS is really enforced.
 */
export async function startHarness(name, env = {}, options = {}) {
  const server = await startPostgres();
  const admin = await server.database(name);
  await migrate(admin, migrationsDirectory);
  await bindEnvironment(admin, 'ci');
  await admin.query('CREATE ROLE heard_test_app LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT');
  await admin.query('GRANT heard_api, heard_job_worker, heard_public_projector, heard_operator TO heard_test_app WITH INHERIT FALSE, SET TRUE');
  await admin.query('GRANT USAGE ON SCHEMA public TO heard_test_app; GRANT SELECT ON heard_schema_migrations, heard_deployment_identity TO heard_test_app');
  const pool = new pg.Pool({ ...server.connection(name, 'heard_test_app'), max: 6 });
  const config = loadConfig({ ...INTAKE_ENV, ...env });
  const app = createHeardServer({ config, pool, logger: silent, ...options });
  return {
    admin, pool, config, app,
    async stop() { await pool.end(); await admin.end(); await server.stop(); },
  };
}

/** Minimal cookie-carrying client for the framework-agnostic app. */
export function client(app, { origin = ORIGIN, ip = '203.0.113.10' } = {}) {
  let cookie = null;
  return {
    get cookie() { return cookie; },
    set cookie(value) { cookie = value; },
    async request(method, path, body, headers = {}) {
      const init = { method, headers: { 'x-forwarded-for': ip, ...headers } };
      if (origin) init.headers.origin = origin;
      if (cookie) init.headers.cookie = cookie;
      if (body !== undefined) { init.headers['content-type'] = 'application/json'; init.body = JSON.stringify(body); }
      const response = await app.handle(new Request(ORIGIN + path, init));
      const set = response.headers.get('set-cookie');
      if (set) cookie = set.split(';')[0].endsWith('=') ? null : set.split(';')[0];
      const text = await response.text();
      return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null, setCookie: set };
    },
  };
}
