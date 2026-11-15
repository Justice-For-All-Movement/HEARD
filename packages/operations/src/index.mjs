/**
 * HEARD-06 operational skeleton: redacted structured logging, liveness that is
 * never readiness, and dependency readiness probes with sanitized output.
 */
import { timingSafeEqual, createHash } from 'node:crypto';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
/** Only these field names are ever written to logs; everything else is redacted. */
export const LOG_FIELD_ALLOWLIST = Object.freeze(new Set([
  'event', 'component', 'status', 'durationMs', 'method', 'route', 'statusCode', 'code', 'release', 'environment',
  'migrationVersion', 'applied', 'attempt', 'jobKind', 'state', 'outcome', 'action', 'reason', 'count', 'driver', 'mode', 'ready',
]));
const SAFE_VALUE = /^[A-Za-z0-9_.:/ -]{0,120}$/;

/** Reduce arbitrary fields to allowlisted, short, token-free primitives. */
export function redactFields(fields = {}) {
  const out = {};
  for (const [key, value] of Object.entries(fields ?? {})) {
    if (!LOG_FIELD_ALLOWLIST.has(key)) { out[key] = '[redacted]'; continue; }
    if (typeof value === 'number' || typeof value === 'boolean' || value === null) { out[key] = value; continue; }
    if (Array.isArray(value) && value.every(v => typeof v === 'number')) { out[key] = value.slice(0, 50); continue; }
    if (typeof value === 'string' && SAFE_VALUE.test(value) && !looksSecret(value)) { out[key] = value; continue; }
    out[key] = '[redacted]';
  }
  return out;
}
function looksSecret(value) {
  return /@/.test(value) || /[A-Za-z0-9+/_-]{32,}/.test(value) || /postgres(ql)?:\/\//i.test(value);
}

export function createLogger({ level = 'info', sink = line => process.stdout.write(line + '\n'), base = {} } = {}) {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const write = (lvl, event, fields) => {
    if (LEVELS[lvl] < threshold) return;
    sink(JSON.stringify({ time: new Date().toISOString(), level: lvl, ...redactFields({ ...base, ...fields, event }) }));
  };
  return Object.freeze({
    debug: (event, fields) => write('debug', event, fields),
    info: (event, fields) => write('info', event, fields),
    warn: (event, fields) => write('warn', event, fields),
    error: (event, fields) => write('error', event, fields),
  });
}

/** Map any thrown value to a stable code; never its message, stack or payload. */
export function errorCode(error) {
  if (error && typeof error === 'object') {
    if (typeof error.code === 'string' && /^[A-Z0-9_]{2,64}$/i.test(error.code)) return error.code;
    if (typeof error.name === 'string' && /^[A-Za-z]{2,64}$/.test(error.name)) return error.name;
  }
  return 'UNKNOWN';
}

export function sanitizedError() {
  return { code: 'SERVICE_UNAVAILABLE', message: 'Service is temporarily unavailable' };
}

/** Liveness: the process can answer. It deliberately carries no dependency claim. */
export function liveness({ release = null } = {}) {
  return { status: 'alive', release, readiness: 'see /api/ready' };
}

/**
 * Run named readiness probes with a timeout. A probe returns
 * {status:'ok'|'not_configured'|'disabled'|'fail', detail?}. Required probes must be 'ok'.
 * @param {{name:string, required:boolean, probe:() => Promise<{status:string, detail?:Record<string,unknown>}>}[]} checks
 */
export async function assessReadiness(checks, { timeoutMs = 3000 } = {}) {
  const components = {};
  await Promise.all(checks.map(async ({ name, required, probe }) => {
    let result;
    let timer;
    try {
      result = await Promise.race([
        probe(),
        new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'PROBE_TIMEOUT' })), timeoutMs); }),
      ]);
    } catch (error) {
      result = { status: 'fail', detail: { code: errorCode(error) } };
    } finally { clearTimeout(timer); }
    if (!result || !['ok', 'not_configured', 'disabled', 'fail'].includes(result.status)) result = { status: 'fail', detail: { code: 'INVALID_PROBE_RESULT' } };
    components[name] = { required, status: result.status, ...(result.detail ? { detail: redactFields(result.detail) } : {}) };
  }));
  const ready = Object.values(components).every(c => !c.required || c.status === 'ok');
  return { ready, components };
}

/** Public readiness body: coarse only. Details require an operator token. */
export function publicReadiness(assessment) {
  return { status: assessment.ready ? 'ready' : 'not_ready' };
}

/** Constant-time bearer token comparison; absent configured token always denies. */
export function operatorAuthorized(authorizationHeader, configuredToken) {
  if (!configuredToken || typeof authorizationHeader !== 'string') return false;
  const match = /^Bearer (\S+)$/.exec(authorizationHeader);
  if (!match) return false;
  const a = createHash('sha256').update(match[1]).digest();
  const b = createHash('sha256').update(configuredToken).digest();
  return timingSafeEqual(a, b);
}
