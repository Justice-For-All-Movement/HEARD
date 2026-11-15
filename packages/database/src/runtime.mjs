import pg from 'pg';

/** Latest checksum-bound migration shipped with this release (asserted by tests against db/migrations). */
export const LATEST_MIGRATION = 9;

export const SCOPED_ROLES = Object.freeze(['heard_api', 'heard_job_worker', 'heard_public_projector', 'heard_operator']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const isUuid = value => typeof value === 'string' && UUID.test(value);

/** Lazily created pool; no connection is attempted until first use. */
export function createPool(database, { max } = {}) {
  if (!database?.url) throw Object.assign(new Error('Database not configured'), { code: 'DATABASE_NOT_CONFIGURED' });
  const pool = new pg.Pool({
    connectionString: database.url,
    max: max ?? database.poolMax ?? 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 15_000,
    application_name: 'heard',
  });
  // An idle client error must not crash the process or log connection details.
  pool.on('error', () => {});
  return pool;
}

/** Run fn inside a transaction on a dedicated pooled client. */
export async function withTransaction(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection already failed */ }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Run fn in a transaction that has dropped to a scoped, RLS-bound role with the
 * authenticated subject (and optional lookup hashes) set as transaction-local settings.
 * Row-level policies then enforce ownership in the database as defense in depth.
 * @param {{role?: string, subjectId?: string|null, settings?: Record<string,string>}} scope
 */
export async function withScope(pool, scope, fn) {
  const role = scope.role ?? 'heard_api';
  if (!SCOPED_ROLES.includes(role)) throw new Error('Unknown scoped role');
  if (scope.subjectId != null && !isUuid(scope.subjectId)) throw new Error('Invalid subject');
  return withTransaction(pool, async client => {
    await client.query(`SET LOCAL ROLE ${role}`);
    await client.query("SELECT set_config('heard.subject_id', $1, true)", [scope.subjectId ?? '']);
    for (const [key, value] of Object.entries(scope.settings ?? {})) {
      if (!/^[a-z_]{1,40}$/.test(key) || typeof value !== 'string') throw new Error('Invalid scoped setting');
      await client.query('SELECT set_config($1, $2, true)', [`heard.${key}`, value]);
    }
    return fn(client);
  });
}

/** Bind the database to HEARD_ENV on first use; refuse a different environment afterwards. */
export async function bindEnvironment(client, environment) {
  await client.query('INSERT INTO heard_deployment_identity(environment) VALUES($1) ON CONFLICT (singleton) DO NOTHING', [environment]);
  const bound = (await client.query('SELECT environment FROM heard_deployment_identity')).rows[0]?.environment;
  if (bound !== environment) throw Object.assign(new Error('Database is bound to a different environment'), { code: 'ENVIRONMENT_MISMATCH' });
  return bound;
}

/** Readiness probe: connectivity, exact migration version and environment binding. */
export async function probeDatabase(pool, { environment }) {
  const client = await pool.connect();
  try {
    const version = (await client.query('SELECT coalesce(max(version),0)::int AS version FROM heard_schema_migrations')).rows[0].version;
    if (version !== LATEST_MIGRATION) return { status: 'fail', detail: { code: version < LATEST_MIGRATION ? 'MIGRATIONS_PENDING' : 'SCHEMA_NEWER_THAN_RELEASE', migrationVersion: version } };
    const bound = (await client.query('SELECT environment FROM heard_deployment_identity')).rows[0]?.environment ?? null;
    if (bound === null) return { status: 'fail', detail: { code: 'ENVIRONMENT_UNBOUND', migrationVersion: version } };
    if (bound !== environment) return { status: 'fail', detail: { code: 'ENVIRONMENT_MISMATCH', migrationVersion: version } };
    return { status: 'ok', detail: { migrationVersion: version } };
  } catch (error) {
    // Undefined table means an empty database.
    if (error?.code === '42P01') return { status: 'fail', detail: { code: 'MIGRATIONS_PENDING', migrationVersion: 0 } };
    throw error;
  } finally {
    client.release();
  }
}
