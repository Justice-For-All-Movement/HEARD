/**
 * HEARD-06 environment configuration schema.
 *
 * Every variable is declared here with its purpose, sensitivity and the external
 * service it refers to. Parsing is strict and fail-closed: an invalid value, or a
 * feature switched on without the secrets it needs, is a startup error. Error
 * messages name variables but never echo their values.
 */

export const ENVIRONMENTS = Object.freeze(['local', 'ci', 'staging', 'production']);
export const STORAGE_DRIVERS = Object.freeze(['none', 'memory', 'filesystem', 's3']);
export const SECURE_INTAKE_MODES = Object.freeze(['local', 'remote']);
export const SCANNER_DRIVERS = Object.freeze(['none', 'fake', 'clamd']);

/** Documentation register; `scripts/check-env-docs.mjs` keeps docs and .env.example aligned. */
export const VARIABLES = Object.freeze({
  HEARD_ENV: { required: 'production deployments', secret: false, service: null, purpose: 'Deployment environment name (local, ci, staging, production). Bound to the database on first migration to prevent cross-connection.' },
  PORT: { required: 'set by Render', secret: false, service: 'Render', purpose: 'HTTP listen port.' },
  HEARD_PUBLIC_ORIGIN: { required: 'when intake is enabled outside local/ci', secret: false, service: null, purpose: 'Canonical https origin used for same-origin (CSRF) checks on mutating requests.' },
  HEARD_BUILD_SHA: { required: false, secret: false, service: null, purpose: 'Release commit reported by /api/health. Falls back to RENDER_GIT_COMMIT.' },
  HEARD_LOG_LEVEL: { required: false, secret: false, service: null, purpose: 'debug, info, warn or error (default info). Logs are structured and redacted.' },
  DATABASE_URL: { required: 'for intake and readiness of private services', secret: true, service: 'Neon PostgreSQL', purpose: 'PostgreSQL connection string for the isolated HEARD database (sslmode=require for Neon).' },
  HEARD_DATABASE_POOL_MAX: { required: false, secret: false, service: null, purpose: 'Maximum pooled connections (default 5).' },
  HEARD_MIGRATE_ON_START: { required: false, secret: false, service: null, purpose: 'When true, the start script applies checksum-bound migrations before serving.' },
  HEARD_OPERATIONS_TOKEN: { required: false, secret: true, service: null, purpose: 'Bearer token for detailed readiness (/api/ready?detail=1). Without it, only coarse status is public.' },
  HEARD_INTAKE_ENABLED: { required: false, secret: false, service: null, purpose: 'Feature flag for anonymous sessions, drafts and private submission (default false).' },
  HEARD_SESSION_SECRET: { required: 'when intake is enabled', secret: true, service: null, purpose: 'At least 32 random bytes (base64/hex) keying session, recovery and receipt verifiers.' },
  HEARD_DATA_ENCRYPTION_KEY: { required: 'when intake is enabled', secret: true, service: null, purpose: 'Exactly 32 random bytes (base64) for AES-256-GCM field encryption of draft answers.' },
  HEARD_DATA_ENCRYPTION_KEY_ID: { required: false, secret: false, service: null, purpose: 'Identifier recorded with each ciphertext to support key rotation (default k1).' },
  HEARD_SECURE_INTAKE_MODE: { required: false, secret: false, service: 'Secure Intake & Case Workflow Engine', purpose: 'local (HEARD-owned PostgreSQL adapter, default) or remote (disabled until an upstream contract is verified).' },
  HEARD_SECURE_INTAKE_URL: { required: 'when mode is remote', secret: false, service: 'Secure Intake & Case Workflow Engine', purpose: 'https base URL of a verified engine deployment.' },
  HEARD_SECURE_INTAKE_API_VERSION: { required: 'when mode is remote', secret: false, service: 'Secure Intake & Case Workflow Engine', purpose: 'Pinned upstream API version (for example v1).' },
  HEARD_SECURE_INTAKE_TOKEN: { required: 'when mode is remote', secret: true, service: 'Secure Intake & Case Workflow Engine', purpose: 'Service credential for the engine.' },
  HEARD_OBJECT_STORAGE_DRIVER: { required: false, secret: false, service: 'Backblaze B2 (S3-compatible)', purpose: 'none (default), memory (tests), filesystem (local) or s3 (B2/S3-compatible).' },
  HEARD_OBJECT_STORAGE_DIR: { required: 'when driver is filesystem', secret: false, service: null, purpose: 'Private local directory for synthetic objects.' },
  HEARD_S3_ENDPOINT: { required: 'when driver is s3', secret: false, service: 'Backblaze B2', purpose: 'S3-compatible https endpoint, e.g. https://s3.us-west-004.backblazeb2.com.' },
  HEARD_S3_REGION: { required: 'when driver is s3', secret: false, service: 'Backblaze B2', purpose: 'Signing region, e.g. us-west-004.' },
  HEARD_S3_BUCKET: { required: 'when driver is s3', secret: false, service: 'Backblaze B2', purpose: 'Private bucket for quarantined uploads and originals.' },
  HEARD_S3_ACCESS_KEY_ID: { required: 'when driver is s3', secret: true, service: 'Backblaze B2', purpose: 'Application key ID scoped to the private bucket.' },
  HEARD_S3_SECRET_ACCESS_KEY: { required: 'when driver is s3', secret: true, service: 'Backblaze B2', purpose: 'Application key scoped to the private bucket.' },
  HEARD_SCANNER_DRIVER: { required: false, secret: false, service: 'Malware scanner (ClamAV clamd)', purpose: 'none (default: uploads stay quarantined), fake (tests only) or clamd.' },
  HEARD_CLAMD_HOST: { required: 'when scanner is clamd', secret: false, service: 'ClamAV clamd', purpose: 'Private-network clamd host.' },
  HEARD_CLAMD_PORT: { required: false, secret: false, service: 'ClamAV clamd', purpose: 'clamd TCP port (default 3310).' },
});

export class ConfigError extends Error {
  constructor(problems) {
    super(`Invalid HEARD configuration: ${problems.join('; ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

const TRUE = new Set(['1', 'true', 'yes', 'on']);
const FALSE = new Set(['', '0', 'false', 'no', 'off']);

function decodeSecret(value) {
  if (/^[0-9a-f]+$/i.test(value) && value.length % 2 === 0) return Buffer.from(value, 'hex');
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return null;
}

/**
 * Parse an environment object into a frozen, typed configuration.
 * @param {Record<string, string|undefined>} env
 */
export function loadConfig(env = process.env) {
  const problems = [];
  const text = name => {
    const value = env[name];
    if (value === undefined) return undefined;
    if (typeof value !== 'string' || /[\u0000-\u001f\u007f]/.test(value)) { problems.push(`${name} contains control characters`); return undefined; }
    const trimmed = value.trim();
    return trimmed === '' ? undefined : trimmed;
  };
  const bool = (name, fallback) => {
    const raw = (text(name) ?? '').toLowerCase();
    if (raw === '') return fallback;
    if (TRUE.has(raw)) return true;
    if (FALSE.has(raw)) return false;
    problems.push(`${name} must be true or false`);
    return fallback;
  };
  const oneOf = (name, allowed, fallback) => {
    const raw = text(name) ?? fallback;
    if (!allowed.includes(raw)) { problems.push(`${name} must be one of ${allowed.join(', ')}`); return fallback; }
    return raw;
  };
  const integer = (name, fallback, min, max) => {
    const raw = text(name);
    if (raw === undefined) return fallback;
    if (!/^\d+$/.test(raw) || Number(raw) < min || Number(raw) > max) { problems.push(`${name} must be an integer between ${min} and ${max}`); return fallback; }
    return Number(raw);
  };
  const httpsUrl = (name, { allowHttpLocal = false } = {}) => {
    const raw = text(name);
    if (raw === undefined) return undefined;
    let url;
    try { url = new URL(raw); } catch { problems.push(`${name} must be an absolute URL`); return undefined; }
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(allowHttpLocal && url.protocol === 'http:' && local)) { problems.push(`${name} must use https`); return undefined; }
    if (url.username || url.password || url.search || url.hash) { problems.push(`${name} must not contain credentials, query or fragment`); return undefined; }
    return url;
  };

  const environment = oneOf('HEARD_ENV', ENVIRONMENTS, env.NODE_ENV === 'production' ? 'production' : 'local');
  const deployed = environment === 'staging' || environment === 'production';
  const logLevel = oneOf('HEARD_LOG_LEVEL', ['debug', 'info', 'warn', 'error'], 'info');
  const publicOrigin = httpsUrl('HEARD_PUBLIC_ORIGIN', { allowHttpLocal: !deployed });

  let database = null;
  const databaseUrl = text('DATABASE_URL');
  if (databaseUrl !== undefined) {
    let parsed;
    try { parsed = new URL(databaseUrl); } catch { problems.push('DATABASE_URL must be a postgres:// or postgresql:// URL'); }
    if (parsed) {
      if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) problems.push('DATABASE_URL must be a postgres:// or postgresql:// URL');
      const sslmode = parsed.searchParams.get('sslmode');
      const localHost = ['localhost', '127.0.0.1', '::1', ''].includes(parsed.hostname) || parsed.hostname.startsWith('/');
      if (deployed && !localHost && !['require', 'verify-ca', 'verify-full'].includes(sslmode ?? '')) problems.push('DATABASE_URL must set sslmode=require (or stricter) for staging/production');
      database = Object.freeze({ url: databaseUrl, poolMax: integer('HEARD_DATABASE_POOL_MAX', 5, 1, 50), migrateOnStart: bool('HEARD_MIGRATE_ON_START', false) });
    }
  } else {
    // Without a database there is nothing to migrate; the flag is validated but has no effect.
    bool('HEARD_MIGRATE_ON_START', false);
  }

  const operationsToken = text('HEARD_OPERATIONS_TOKEN');
  if (operationsToken !== undefined && operationsToken.length < 32) problems.push('HEARD_OPERATIONS_TOKEN must be at least 32 characters');

  const intakeEnabled = bool('HEARD_INTAKE_ENABLED', false);
  let sessionSecret = null;
  let dataKey = null;
  const rawSession = text('HEARD_SESSION_SECRET');
  if (rawSession !== undefined) {
    const decoded = decodeSecret(rawSession);
    if (!decoded || decoded.length < 32) problems.push('HEARD_SESSION_SECRET must encode at least 32 random bytes (hex or base64)');
    else sessionSecret = decoded;
  }
  const rawKey = text('HEARD_DATA_ENCRYPTION_KEY');
  if (rawKey !== undefined) {
    const decoded = decodeSecret(rawKey);
    if (!decoded || decoded.length !== 32) problems.push('HEARD_DATA_ENCRYPTION_KEY must encode exactly 32 bytes (hex or base64)');
    else dataKey = decoded;
  }
  const dataKeyId = text('HEARD_DATA_ENCRYPTION_KEY_ID') ?? 'k1';
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(dataKeyId)) problems.push('HEARD_DATA_ENCRYPTION_KEY_ID must be 1-32 characters of [A-Za-z0-9_-]');
  if (sessionSecret && dataKey && sessionSecret.equals(dataKey)) problems.push('HEARD_SESSION_SECRET and HEARD_DATA_ENCRYPTION_KEY must be different keys');

  if (intakeEnabled) {
    if (!database) problems.push('HEARD_INTAKE_ENABLED requires DATABASE_URL');
    if (!sessionSecret) problems.push('HEARD_INTAKE_ENABLED requires HEARD_SESSION_SECRET');
    if (!dataKey) problems.push('HEARD_INTAKE_ENABLED requires HEARD_DATA_ENCRYPTION_KEY');
    if (deployed && !publicOrigin) problems.push('HEARD_INTAKE_ENABLED requires HEARD_PUBLIC_ORIGIN in staging/production');
  }

  const intakeMode = oneOf('HEARD_SECURE_INTAKE_MODE', SECURE_INTAKE_MODES, 'local');
  let secureIntake = Object.freeze({ mode: 'local' });
  if (intakeMode === 'remote') {
    const url = httpsUrl('HEARD_SECURE_INTAKE_URL');
    const apiVersion = text('HEARD_SECURE_INTAKE_API_VERSION');
    const token = text('HEARD_SECURE_INTAKE_TOKEN');
    if (!url) problems.push('HEARD_SECURE_INTAKE_MODE=remote requires HEARD_SECURE_INTAKE_URL');
    if (!apiVersion || !/^v[1-9]\d*$/.test(apiVersion)) problems.push('HEARD_SECURE_INTAKE_MODE=remote requires HEARD_SECURE_INTAKE_API_VERSION like v1');
    if (!token) problems.push('HEARD_SECURE_INTAKE_MODE=remote requires HEARD_SECURE_INTAKE_TOKEN');
    secureIntake = Object.freeze({ mode: 'remote', url: url?.href ?? null, apiVersion: apiVersion ?? null, token: token ?? null });
  }

  const storageDriver = oneOf('HEARD_OBJECT_STORAGE_DRIVER', STORAGE_DRIVERS, 'none');
  let objectStorage = Object.freeze({ driver: storageDriver });
  if (storageDriver === 'memory' && deployed) problems.push('HEARD_OBJECT_STORAGE_DRIVER=memory is only for local/ci');
  if (storageDriver === 'filesystem') {
    const directory = text('HEARD_OBJECT_STORAGE_DIR');
    if (!directory) problems.push('HEARD_OBJECT_STORAGE_DRIVER=filesystem requires HEARD_OBJECT_STORAGE_DIR');
    if (deployed) problems.push('HEARD_OBJECT_STORAGE_DRIVER=filesystem is only for local/ci');
    objectStorage = Object.freeze({ driver: 'filesystem', directory: directory ?? null });
  }
  if (storageDriver === 's3') {
    const endpoint = httpsUrl('HEARD_S3_ENDPOINT', { allowHttpLocal: !deployed });
    const fields = { region: text('HEARD_S3_REGION'), bucket: text('HEARD_S3_BUCKET'), accessKeyId: text('HEARD_S3_ACCESS_KEY_ID'), secretAccessKey: text('HEARD_S3_SECRET_ACCESS_KEY') };
    if (!endpoint) problems.push('HEARD_OBJECT_STORAGE_DRIVER=s3 requires HEARD_S3_ENDPOINT');
    for (const [key, name] of [['region', 'HEARD_S3_REGION'], ['bucket', 'HEARD_S3_BUCKET'], ['accessKeyId', 'HEARD_S3_ACCESS_KEY_ID'], ['secretAccessKey', 'HEARD_S3_SECRET_ACCESS_KEY']]) {
      if (!fields[key]) problems.push(`HEARD_OBJECT_STORAGE_DRIVER=s3 requires ${name}`);
    }
    if (fields.bucket && !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(fields.bucket)) problems.push('HEARD_S3_BUCKET is not a valid bucket name');
    objectStorage = Object.freeze({ driver: 's3', endpoint: endpoint?.origin ?? null, ...fields });
  }

  const scannerDriver = oneOf('HEARD_SCANNER_DRIVER', SCANNER_DRIVERS, 'none');
  let scanner = Object.freeze({ driver: scannerDriver });
  if (scannerDriver === 'fake' && deployed) problems.push('HEARD_SCANNER_DRIVER=fake is only for local/ci');
  if (scannerDriver === 'clamd') {
    const host = text('HEARD_CLAMD_HOST');
    if (!host) problems.push('HEARD_SCANNER_DRIVER=clamd requires HEARD_CLAMD_HOST');
    scanner = Object.freeze({ driver: 'clamd', host: host ?? null, port: integer('HEARD_CLAMD_PORT', 3310, 1, 65535) });
  }

  const release = text('HEARD_BUILD_SHA') ?? text('RENDER_GIT_COMMIT') ?? null;
  if (release !== null && !/^[a-f0-9]{7,40}$/.test(release)) problems.push('HEARD_BUILD_SHA must be a hexadecimal commit id');

  if (problems.length) throw new ConfigError(problems);
  return deepFreeze({
    environment,
    deployed,
    logLevel,
    publicOrigin: publicOrigin?.origin ?? null,
    release,
    port: integer('PORT', 3000, 1, 65535),
    database,
    operationsToken: operationsToken ?? null,
    intake: { enabled: intakeEnabled },
    secrets: { sessionSecret, dataKey, dataKeyId },
    secureIntake,
    objectStorage,
    scanner,
  });
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Buffer.isBuffer(value) && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Non-secret summary safe to print at startup or return to an authenticated operator. */
export function describeConfig(config) {
  return {
    environment: config.environment,
    release: config.release,
    databaseConfigured: Boolean(config.database),
    migrateOnStart: Boolean(config.database?.migrateOnStart),
    intakeEnabled: config.intake.enabled,
    secureIntakeMode: config.secureIntake.mode,
    objectStorageDriver: config.objectStorage.driver,
    scannerDriver: config.scanner.driver,
    publicOrigin: config.publicOrigin,
    operationsTokenConfigured: Boolean(config.operationsToken),
  };
}
