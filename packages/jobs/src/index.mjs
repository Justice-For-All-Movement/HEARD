/**
 * HEARD-15 durable job framework (PostgreSQL-backed; no extra infrastructure).
 *
 * - Enqueue is transactional with the caller's write and deduplicated by key, so a
 *   retried request never creates a second job.
 * - Workers lease ready jobs with FOR UPDATE SKIP LOCKED under the job worker role,
 *   scoped by RLS to the declared job kind. A killed worker's lease simply expires and
 *   another worker resumes the job.
 * - A handler does its (idempotent, read-mostly) work outside the database and returns
 *   a `commit` callback; the commit runs in one transaction only if the worker still
 *   owns the lease, so a cancelled, re-leased or duplicate run can never apply side
 *   effects twice.
 * - Each run has a wall-clock budget (AbortSignal). Retryable failures back off;
 *   permanent failures and exhausted retries dead-letter the job (state `failed` with
 *   an error code) without affecting other jobs. Payloads are small allowlisted
 *   metadata, never content.
 */
import { randomUUID } from 'node:crypto';
import { withScope } from '@heard/database';

export const DEFAULT_BACKOFF_MS = Object.freeze([30_000, 120_000, 600_000]);
export const MAX_ACTIVE_JOBS_PER_CASE = 50;

export class JobError extends Error {
  /** @param {string} code  @param {{retryable?: boolean}} [options] */
  constructor(code, { retryable = true } = {}) { super(code); this.code = code; this.retryable = retryable; this.name = 'JobError'; }
}
export const permanent = code => new JobError(code, { retryable: false });

const KIND = /^[a-z][a-z0-9_]{1,63}$/;
const PAYLOAD_VALUE = /^[A-Za-z0-9_.:-]{0,128}$/;
export function sanitizePayload(payload = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw permanent('JOB_PAYLOAD_INVALID');
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (!/^[a-z][a-zA-Z0-9]{0,31}$/.test(k)) throw permanent('JOB_PAYLOAD_INVALID');
    if (!(typeof v === 'number' && Number.isFinite(v)) && !(typeof v === 'boolean') && !(typeof v === 'string' && PAYLOAD_VALUE.test(v))) throw permanent('JOB_PAYLOAD_INVALID');
    out[k] = v;
  }
  return out;
}

/**
 * Enqueue inside the caller's transaction. Returns {jobId, created}; a duplicate
 * dedupe key returns the existing job instead of creating another.
 */
export async function enqueue(client, { kind, caseId, objectId = null, dedupeKey, payload = {}, maxAttempts = 4, availableAt = null }) {
  if (!KIND.test(kind)) throw permanent('JOB_KIND_INVALID');
  if (typeof dedupeKey !== 'string' || dedupeKey.length < 1 || dedupeKey.length > 200) throw permanent('JOB_DEDUPE_INVALID');
  const active = (await client.query("SELECT count(*)::int AS n FROM heard_jobs WHERE case_id=$1 AND state IN ('queued','leased')", [caseId])).rows[0]?.n ?? 0;
  if (active >= MAX_ACTIVE_JOBS_PER_CASE) throw permanent('JOB_QUOTA_REACHED');
  const inserted = await client.query(
    `INSERT INTO heard_jobs(case_id, object_id, kind, dedupe_key, payload, max_attempts, available_at)
     VALUES($1,$2,$3,$4,$5,$6,coalesce($7, now())) ON CONFLICT (dedupe_key) DO NOTHING RETURNING id`,
    [caseId, objectId, kind, dedupeKey, sanitizePayload(payload), maxAttempts, availableAt]);
  if (inserted.rows[0]) return { jobId: inserted.rows[0].id, created: true };
  const existing = (await client.query('SELECT id FROM heard_jobs WHERE dedupe_key=$1', [dedupeKey])).rows[0];
  return { jobId: existing?.id ?? null, created: false };
}

const scopeFor = (kind, extra = {}) => ({ role: 'heard_job_worker', settings: { job_purpose: kind, ...extra } });

/** Lease up to `limit` ready jobs of one kind. Exhausted jobs whose lease expired are dead-lettered first. */
export async function lease(pool, { kind, workerId, limit = 5, leaseMs = 10 * 60_000, settings = {} }) {
  return withScope(pool, scopeFor(kind, settings), async client => {
    await client.query("UPDATE heard_jobs SET state='failed', lease_owner=NULL, lease_until=NULL, last_error_code='LEASE_EXPIRED', finished_at=now() WHERE kind=$1 AND state='leased' AND lease_until < now() AND attempts >= max_attempts", [kind]);
    const ids = (await client.query(
      "SELECT id FROM heard_jobs WHERE kind=$1 AND attempts < max_attempts AND available_at <= now() AND (state='queued' OR (state='leased' AND lease_until < now())) ORDER BY available_at, created_at LIMIT $2 FOR UPDATE SKIP LOCKED",
      [kind, limit])).rows.map(r => r.id);
    if (!ids.length) return [];
    return (await client.query(
      "UPDATE heard_jobs SET state='leased', lease_owner=$2, lease_until=now() + ($3::int * interval '1 millisecond'), attempts=attempts+1 WHERE id = ANY($1::uuid[]) RETURNING id, case_id, object_id, payload, attempts, max_attempts",
      [ids, workerId, leaseMs])).rows.map(r => ({ id: r.id, caseId: r.case_id, objectId: r.object_id, payload: r.payload, attempts: r.attempts, maxAttempts: r.max_attempts }));
  });
}

function withBudget(promiseFactory, timeoutMs) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new JobError('JOB_TIMEOUT')); }, timeoutMs); });
  return Promise.race([promiseFactory(controller.signal), timeout]).finally(() => clearTimeout(timer));
}

/**
 * Run one batch for a kind.
 * @param {{kind:string, handler:(job, ctx:{signal:AbortSignal, read:(fn)=>Promise<any>}) => Promise<{commit?:(client)=>Promise<void>, onFailure?:(client, info)=>Promise<void>}>, workerId?:string, limit?:number, leaseMs?:number, timeoutMs?:number, backoffMs?:readonly number[], settings?:Record<string,string>}} options
 */
export async function runJobs(pool, { kind, handler, onFailure, workerId = randomUUID(), limit = 5, leaseMs = 10 * 60_000, timeoutMs = 5 * 60_000, backoffMs = DEFAULT_BACKOFF_MS, settings = {} }) {
  const scope = scopeFor(kind, settings);
  const jobs = await lease(pool, { kind, workerId, limit, leaseMs, settings });
  const results = [];
  for (const job of jobs) {
    let outcome;
    try {
      const read = fn => withScope(pool, scope, fn);
      const result = await withBudget(signal => handler(job, { signal, read }), Math.min(timeoutMs, leaseMs));
      outcome = { status: 'succeeded', commit: result?.commit };
    } catch (error) {
      const code = error instanceof JobError ? error.code : 'JOB_HANDLER_ERROR';
      const exhausted = job.attempts >= job.maxAttempts;
      outcome = { status: error instanceof JobError && !error.retryable ? 'dead' : exhausted ? 'dead' : 'retry', code };
    }
    const applied = await withScope(pool, scope, async client => {
      // Compare-and-set on lease ownership: cancelled, expired-and-re-leased or duplicate runs apply nothing.
      const owned = (await client.query("SELECT 1 FROM heard_jobs WHERE id=$1 AND state='leased' AND lease_owner=$2 FOR UPDATE", [job.id, workerId])).rows.length;
      if (!owned) return 'lease_lost';
      if (outcome.status === 'succeeded') {
        if (outcome.commit) await outcome.commit(client);
        await client.query("UPDATE heard_jobs SET state='succeeded', lease_owner=NULL, lease_until=NULL, last_error_code=NULL, finished_at=now() WHERE id=$1", [job.id]);
        return 'succeeded';
      }
      if (onFailure) await onFailure(client, { job, code: outcome.code, final: outcome.status === 'dead' });
      if (outcome.status === 'dead') {
        await client.query("UPDATE heard_jobs SET state='failed', lease_owner=NULL, lease_until=NULL, last_error_code=$2, finished_at=now() WHERE id=$1", [job.id, outcome.code]);
        return 'dead_lettered';
      }
      const delay = backoffMs[Math.min(job.attempts - 1, backoffMs.length - 1)] ?? 0;
      await client.query("UPDATE heard_jobs SET state='queued', lease_owner=NULL, lease_until=NULL, last_error_code=$2, available_at=now() + ($3::int * interval '1 millisecond') WHERE id=$1", [job.id, outcome.code, delay]);
      return 'retry';
    }).catch(error => {
      // A failing commit must not lose the job: release it for a later retry.
      return withScope(pool, scope, c => c.query("UPDATE heard_jobs SET state='queued', lease_owner=NULL, lease_until=NULL, last_error_code='JOB_COMMIT_FAILED' WHERE id=$1 AND lease_owner=$2", [job.id, workerId])).then(() => `commit_failed:${error?.code ?? 'unknown'}`);
    });
    results.push({ jobId: job.id, objectId: job.objectId, outcome: applied, code: outcome.code ?? null });
  }
  return results;
}

/** Contributor-visible status of jobs on their case (no payloads or worker identities). */
export async function caseJobs(client, caseId) {
  return (await client.query('SELECT id, kind, object_id, state, attempts, max_attempts, last_error_code, created_at, finished_at FROM heard_jobs WHERE case_id=$1 ORDER BY created_at', [caseId])).rows
    .map(r => ({ jobId: r.id, kind: r.kind, objectId: r.object_id, state: r.state, attempts: r.attempts, maxAttempts: r.max_attempts, errorCode: r.last_error_code, createdAt: r.created_at, finishedAt: r.finished_at }));
}

/** Cancel a not-yet-finished job on the caller's own case (RLS enforces ownership). */
export async function cancelJob(client, jobId) {
  const result = await client.query("UPDATE heard_jobs SET state='cancelled', cancelled_at=now(), finished_at=now(), lease_owner=NULL, lease_until=NULL WHERE id=$1 AND state IN ('queued','leased')", [jobId]);
  if (result.rowCount !== 1) throw permanent('NOT_FOUND');
}
