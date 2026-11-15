/**
 * HEARD-13 malware quarantine and parser safety.
 *
 * A leased worker re-verifies each quarantined object's bytes against its recorded
 * SHA-256, detects the real type from magic bytes (never trusting the declared type
 * or extension), refuses PDFs with active content and polyglot markers, and asks a
 * malware scanner for a verdict. Only "clean + verified type + named engine"
 * clears an object (also enforced by a database constraint). Scanner absence,
 * errors and timeouts leave the object quarantined and retry with backoff; after
 * the last attempt it stays quarantined as `scan_failed`. No parser executes the
 * content: detection reads bytes only.
 */
import { createHash, randomUUID } from 'node:crypto';
import { connect } from 'node:net';
import { withScope } from '@heard/database';

export class ScanError extends Error {
  constructor(code) { super(code); this.code = code; this.name = 'ScanError'; }
}

/** Detect a media type from the first bytes. Returns null when unrecognised. */
export function detectType(head) {
  const b = Buffer.from(head ?? []);
  const at = (offset, bytes) => b.length >= offset + bytes.length && bytes.every((v, i) => b[offset + i] === v);
  if (at(0, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (at(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (b.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
  if (b.subarray(4, 8).toString('latin1') === 'ftyp') {
    const brand = b.subarray(8, 12).toString('latin1');
    if (brand === 'qt  ') return 'video/quicktime';
    if (brand === 'M4A ' || brand === 'M4B ') return 'audio/mp4';
    if (['isom', 'iso2', 'iso4', 'iso5', 'iso6', 'mp41', 'mp42', 'avc1', 'M4V ', 'dash', 'MSNV'].includes(brand)) return 'video/mp4';
    return null;
  }
  if (at(0, [0x49, 0x44, 0x33])) return 'audio/mpeg';
  if (b.length >= 2 && b[0] === 0xff && (b[1] & 0xe0) === 0xe0 && (b[1] & 0x06) !== 0) return 'audio/mpeg';
  return null;
}

/** Markers that make an otherwise valid file dangerous or ambiguous. */
const PDF_ACTIVE = [/\/JavaScript\b/, /\/JS\b/, /\/Launch\b/, /\/EmbeddedFiles?\b/, /\/RichMedia\b/, /\/XFA\b/, /\/AA\b/, /\/SubmitForm\b/, /\/ImportData\b/];
const POLYGLOT = [/<script\b/i, /<html\b/i, /<svg\b/i, /PK\x03\x04/, /%PDF-/];

/**
 * Stream an object once: digest, size, detected type and content-safety findings.
 * @returns {Promise<{sha256:string, size:number, detectedType:string|null, finding:string|null}>}
 */
export async function inspectObject(chunks, { maxBytes, declaredType }) {
  const hash = createHash('sha256');
  let size = 0;
  let head = Buffer.alloc(0);
  let tail = '';
  let finding = null;
  for await (const chunk of chunks) {
    size += chunk.length;
    if (size > maxBytes) return { sha256: '', size, detectedType: null, finding: 'oversize' };
    hash.update(chunk);
    if (head.length < 64) head = Buffer.concat([head, chunk.subarray(0, 64 - head.length)]);
    const text = tail + chunk.toString('latin1');
    if (!finding && declaredType === 'application/pdf' && PDF_ACTIVE.some(re => re.test(text))) finding = 'pdf_active_content';
    if (!finding && declaredType !== 'application/pdf' && size <= 1024 * 1024 && POLYGLOT.some(re => re.test(text))) finding = 'polyglot_marker';
    tail = text.slice(-32);
  }
  return { sha256: hash.digest('hex'), size, detectedType: detectType(head), finding };
}

// ---------------------------------------------------------------------------
// Scanner adapters. A scanner returns {verdict:'clean'|'infected', engine, signature?}
// or throws ScanError('SCANNER_UNAVAILABLE'|'SCANNER_ERROR'|'SCAN_TIMEOUT').

/** No scanner configured: every scan is unavailable, so nothing is ever cleared. */
export function createNoScanner() {
  return { engine: null, async health() { return { status: 'fail', detail: { code: 'SCANNER_NOT_CONFIGURED' } }; }, async scan() { throw new ScanError('SCANNER_UNAVAILABLE'); } };
}

/** Test-only scanner that flags the standard EICAR anti-malware test string. */
export const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join('');
export function createFakeScanner({ fail = false } = {}) {
  return {
    engine: 'fake-eicar/1',
    async health() { return { status: 'ok', detail: { driver: 'fake' } }; },
    async scan(chunks) {
      if (fail) throw new ScanError('SCANNER_ERROR');
      let tail = '';
      for await (const chunk of chunks) {
        const text = tail + chunk.toString('latin1');
        if (text.includes(EICAR)) return { verdict: 'infected', engine: 'fake-eicar/1', signature: 'Eicar-Test-Signature' };
        tail = text.slice(-EICAR.length);
      }
      return { verdict: 'clean', engine: 'fake-eicar/1' };
    },
  };
}

/** ClamAV clamd over TCP using the INSTREAM protocol, with an overall deadline. */
export function createClamdScanner({ host, port = 3310, timeoutMs = 120_000 }) {
  const call = (writer) => new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    let reply = '';
    const timer = setTimeout(() => { socket.destroy(); reject(new ScanError('SCAN_TIMEOUT')); }, timeoutMs);
    socket.on('data', d => { reply += d.toString('utf8'); if (reply.length > 4096) socket.destroy(); });
    socket.on('error', () => { clearTimeout(timer); reject(new ScanError('SCANNER_UNAVAILABLE')); });
    socket.on('close', () => { clearTimeout(timer); resolve(reply.replace(/\0/g, '').trim()); });
    socket.on('connect', () => writer(socket).catch(() => { clearTimeout(timer); socket.destroy(); reject(new ScanError('SCANNER_ERROR')); }));
  });
  const write = (socket, data) => new Promise((resolve, reject) => socket.write(data, error => (error ? reject(error) : resolve())));
  return {
    engine: 'clamav-clamd',
    async health() {
      const reply = await call(async s => { await write(s, 'zPING\0'); });
      return reply === 'PONG' ? { status: 'ok', detail: { driver: 'clamd' } } : { status: 'fail', detail: { code: 'SCANNER_BAD_REPLY' } };
    },
    async scan(chunks) {
      const reply = await call(async socket => {
        await write(socket, 'zINSTREAM\0');
        for await (const chunk of chunks) {
          for (let i = 0; i < chunk.length; i += 64 * 1024) {
            const part = chunk.subarray(i, i + 64 * 1024);
            const length = Buffer.alloc(4); length.writeUInt32BE(part.length);
            await write(socket, Buffer.concat([length, part]));
          }
        }
        await write(socket, Buffer.alloc(4));
      });
      if (/^stream: OK$/.test(reply)) return { verdict: 'clean', engine: 'clamav-clamd' };
      const found = /^stream: (.{1,120}) FOUND$/.exec(reply);
      if (found) return { verdict: 'infected', engine: 'clamav-clamd', signature: found[1] };
      // "INSTREAM size limit exceeded", "... ERROR" or anything unexpected is not a verdict.
      throw new ScanError('SCANNER_ERROR');
    },
  };
}

export function selectScanner(scannerConfig) {
  if (scannerConfig?.driver === 'fake') return createFakeScanner();
  if (scannerConfig?.driver === 'clamd') return createClamdScanner(scannerConfig);
  return createNoScanner();
}

// ---------------------------------------------------------------------------
// Job processing.

export const RETRY_BACKOFF_MS = [30_000, 120_000, 600_000];
const SIZE_LIMIT = 300 * 1024 * 1024;

/** Enqueue a scan for a just-quarantined object (runs in the uploader's scoped transaction). */
export async function enqueueScan(client, { objectId, caseId }) {
  await client.query("INSERT INTO heard_jobs(case_id, object_id, kind, dedupe_key, max_attempts) VALUES($1,$2,'scan',$3,4)", [caseId, objectId, `scan:${objectId}`]);
}

const scope = { role: 'heard_job_worker', settings: { job_purpose: 'scan' } };

/** Lease up to `limit` ready scan jobs (queued, or leased with an expired lease). */
async function lease(pool, workerId, { limit, leaseMs }) {
  return withScope(pool, scope, async client => {
    // Exhausted jobs whose last lease expired are closed as failed; their objects stay quarantined.
    await client.query("UPDATE heard_jobs SET state='failed', lease_owner=NULL, lease_until=NULL, last_error_code='LEASE_EXPIRED', finished_at=now() WHERE kind='scan' AND state='leased' AND lease_until < now() AND attempts >= max_attempts");
    const ids = (await client.query(
      "SELECT id FROM heard_jobs WHERE kind='scan' AND attempts < max_attempts AND available_at <= now() AND (state='queued' OR (state='leased' AND lease_until < now())) ORDER BY available_at LIMIT $1 FOR UPDATE SKIP LOCKED", [limit])).rows.map(r => r.id);
    if (!ids.length) return [];
    return (await client.query(
      "UPDATE heard_jobs SET state='leased', lease_owner=$2, lease_until=now() + ($3::int * interval '1 millisecond'), attempts=attempts+1 WHERE id = ANY($1::uuid[]) RETURNING id, object_id, attempts, max_attempts",
      [ids, workerId, leaseMs])).rows;
  });
}

/** Decide the outcome for one object. Pure apart from reading bytes. */
export async function evaluateObject({ storage, scanner, object }) {
  const maxBytes = Math.min(Number(object.size_bytes ?? SIZE_LIMIT), SIZE_LIMIT);
  const inspection = await inspectObject(storage.getObject(object.storage_ref), { maxBytes, declaredType: object.declared_type });
  if (inspection.finding === 'oversize' || inspection.size !== Number(object.size_bytes) || inspection.sha256 !== object.checksum_sha256) return { state: 'rejected', reason: 'integrity_mismatch', detectedType: inspection.detectedType };
  if (!inspection.detectedType || inspection.detectedType !== object.declared_type) return { state: 'rejected', reason: 'type_mismatch', detectedType: inspection.detectedType };
  if (inspection.finding) return { state: 'rejected', reason: inspection.finding, detectedType: inspection.detectedType };
  const result = await scanner.scan(storage.getObject(object.storage_ref));
  if (result.verdict === 'infected') return { state: 'rejected', reason: 'malware', verdict: 'infected', engine: result.engine, detectedType: inspection.detectedType };
  if (result.verdict === 'clean' && result.engine) return { state: 'cleared', reason: null, verdict: 'clean', engine: result.engine, detectedType: inspection.detectedType };
  throw new ScanError('SCANNER_ERROR');
}

/**
 * Process ready scan jobs once. Safe to run concurrently in several workers
 * (SKIP LOCKED leasing; compare-and-set completion by lease owner).
 */
export async function processScanJobs(pool, { storage, scanner, workerId = randomUUID(), limit = 5, leaseMs = 10 * 60_000 } = {}) {
  const jobs = await lease(pool, workerId, { limit, leaseMs });
  const outcomes = [];
  for (const job of jobs) {
    let outcome;
    try {
      const object = await withScope(pool, scope, async c => (await c.query('SELECT id, storage_ref, checksum_sha256, declared_type, size_bytes FROM heard_private_objects WHERE id=$1', [job.object_id])).rows[0]);
      if (!object) throw new ScanError('OBJECT_NOT_VISIBLE');
      outcome = await evaluateObject({ storage, scanner, object });
    } catch (error) {
      outcome = { state: 'retry', code: error instanceof ScanError ? error.code : 'SCAN_INTERNAL_ERROR' };
    }
    await withScope(pool, scope, async client => {
      const owned = (await client.query("SELECT 1 FROM heard_jobs WHERE id=$1 AND state='leased' AND lease_owner=$2 FOR UPDATE", [job.id, workerId])).rows.length;
      if (!owned) return; // lease lost; another worker owns the job now
      if (outcome.state === 'retry') {
        const exhausted = job.attempts >= job.max_attempts;
        const verdict = outcome.code === 'SCANNER_UNAVAILABLE' ? 'unavailable' : 'error';
        await client.query("UPDATE heard_private_objects SET scan_verdict=$2, quarantine_reason=$3 WHERE id=$1 AND quarantine_state='quarantined'", [job.object_id, verdict, exhausted ? 'scan_failed' : 'scan_pending']);
        await client.query(
          `UPDATE heard_jobs SET state=$2, lease_owner=NULL, lease_until=NULL, last_error_code=$3, available_at=now() + ($4::int * interval '1 millisecond'), finished_at=CASE WHEN $2='failed' THEN now() END WHERE id=$1`,
          [job.id, exhausted ? 'failed' : 'queued', outcome.code, RETRY_BACKOFF_MS[Math.min(job.attempts - 1, RETRY_BACKOFF_MS.length - 1)]]);
      } else {
        await client.query(
          "UPDATE heard_private_objects SET quarantine_state=$2, quarantine_reason=$3, scan_verdict=$4, scan_engine=$5, scanned_at=now(), detected_type=$6 WHERE id=$1 AND quarantine_state='quarantined'",
          [job.object_id, outcome.state, outcome.reason, outcome.verdict ?? null, outcome.engine ?? null, outcome.detectedType ?? null]);
        await client.query("UPDATE heard_jobs SET state='succeeded', lease_owner=NULL, lease_until=NULL, last_error_code=NULL, finished_at=now() WHERE id=$1", [job.id]);
      }
    });
    outcomes.push({ jobId: job.id, objectId: job.object_id, state: outcome.state, reason: outcome.reason ?? outcome.code ?? null });
  }
  return outcomes;
}
