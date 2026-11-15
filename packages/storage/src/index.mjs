/**
 * HEARD-12 private object storage behind one interface.
 *
 * Adapters: `memory` (tests), `filesystem` (local synthetic data) and `s3`
 * (Backblaze B2 / any S3-compatible API, AWS Signature V4, path-style, no SDK).
 * Keys are opaque server-generated identifiers; no filename or user text ever
 * becomes part of a key. There is no public URL operation in this interface.
 */
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm, stat, writeFile, open } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export class StorageError extends Error {
  constructor(code) { super(code); this.code = code; this.name = 'StorageError'; }
}

const KEY = /^(quarantine|originals|derivatives)\/[0-9a-f-]{36}$/;
export function assertKey(key) {
  if (typeof key !== 'string' || !KEY.test(key)) throw new StorageError('STORAGE_KEY_INVALID');
}
export const quarantineKey = () => `quarantine/${randomUUID()}`;
const sha256 = data => createHash('sha256').update(data).digest('hex');

/** In-memory adapter for tests. */
export function createMemoryStorage() {
  const objects = new Map();
  const uploads = new Map();
  return {
    driver: 'memory',
    async health() { return { status: 'ok', detail: { driver: 'memory' } }; },
    async createMultipart(key) { assertKey(key); const id = randomUUID(); uploads.set(id, { key, parts: new Map() }); return id; },
    async uploadPart(key, uploadId, partNumber, bytes) {
      const u = uploads.get(uploadId);
      if (!u || u.key !== key) throw new StorageError('STORAGE_UPLOAD_UNKNOWN');
      u.parts.set(partNumber, Buffer.from(bytes));
      return `"${sha256(bytes)}"`;
    },
    async completeMultipart(key, uploadId, parts) {
      const u = uploads.get(uploadId);
      if (!u || u.key !== key) throw new StorageError('STORAGE_UPLOAD_UNKNOWN');
      const buffers = parts.map(p => {
        const b = u.parts.get(p.partNumber);
        if (!b || `"${sha256(b)}"` !== p.etag) throw new StorageError('STORAGE_PART_MISMATCH');
        return b;
      });
      objects.set(key, Buffer.concat(buffers));
      uploads.delete(uploadId);
    },
    async abortMultipart(key, uploadId) { uploads.delete(uploadId); },
    async *getObject(key) { assertKey(key); const b = objects.get(key); if (!b) throw new StorageError('STORAGE_NOT_FOUND'); for (let i = 0; i < b.length; i += 64 * 1024) yield b.subarray(i, i + 64 * 1024); },
    async deleteObject(key) { assertKey(key); objects.delete(key); },
    async exists(key) { return objects.has(key); },
    _objects: objects,
  };
}

/** Filesystem adapter for local development with synthetic files. Directory is private (0700). */
export function createFilesystemStorage(directory) {
  const root = resolve(directory);
  const path = key => { assertKey(key); return join(root, ...key.split('/')); };
  const partsDir = uploadId => join(root, '.multipart', uploadId);
  return {
    driver: 'filesystem',
    async health() {
      await mkdir(root, { recursive: true, mode: 0o700 });
      const s = await stat(root);
      return s.isDirectory() ? { status: 'ok', detail: { driver: 'filesystem' } } : { status: 'fail', detail: { code: 'STORAGE_DIR_INVALID' } };
    },
    async createMultipart(key) {
      assertKey(key);
      const id = randomUUID();
      await mkdir(partsDir(id), { recursive: true, mode: 0o700 });
      await writeFile(join(partsDir(id), 'key'), key, { mode: 0o600 });
      return id;
    },
    async uploadPart(key, uploadId, partNumber, bytes) {
      if (!/^[0-9a-f-]{36}$/.test(uploadId) || (await readFile(join(partsDir(uploadId), 'key'), 'utf8').catch(() => null)) !== key) throw new StorageError('STORAGE_UPLOAD_UNKNOWN');
      await writeFile(join(partsDir(uploadId), String(partNumber).padStart(5, '0')), bytes, { mode: 0o600 });
      return `"${sha256(bytes)}"`;
    },
    async completeMultipart(key, uploadId, parts) {
      if ((await readFile(join(partsDir(uploadId), 'key'), 'utf8').catch(() => null)) !== key) throw new StorageError('STORAGE_UPLOAD_UNKNOWN');
      const target = path(key);
      await mkdir(join(target, '..'), { recursive: true, mode: 0o700 });
      const handle = await open(target, 'wx', 0o600);
      try {
        for (const p of parts) {
          const b = await readFile(join(partsDir(uploadId), String(p.partNumber).padStart(5, '0'))).catch(() => null);
          if (!b || `"${sha256(b)}"` !== p.etag) throw new StorageError('STORAGE_PART_MISMATCH');
          await handle.write(b);
        }
      } catch (error) { await handle.close(); await rm(target, { force: true }); throw error; }
      await handle.close();
      await rm(partsDir(uploadId), { recursive: true, force: true });
    },
    async abortMultipart(key, uploadId) { if (/^[0-9a-f-]{36}$/.test(uploadId)) await rm(partsDir(uploadId), { recursive: true, force: true }); },
    async *getObject(key) {
      const handle = await open(path(key), 'r').catch(() => { throw new StorageError('STORAGE_NOT_FOUND'); });
      try { for await (const chunk of handle.createReadStream({ highWaterMark: 64 * 1024 })) yield chunk; } finally { await handle.close().catch(() => {}); }
    },
    async deleteObject(key) { await rm(path(key), { force: true }); },
    async exists(key) { return stat(path(key)).then(() => true, () => false); },
    async _list() { return readdir(root, { recursive: true }); },
  };
}

// ---------------------------------------------------------------------------
// AWS Signature Version 4 (header-based) for S3-compatible APIs.
const enc = s => encodeURIComponent(s).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
export const EMPTY_SHA256 = sha256('');

/**
 * Sign a request. Returns the headers to send (including Authorization).
 * @param {{method:string, url:URL, headers?:Record<string,string>, payloadSha256:string, region:string, accessKeyId:string, secretAccessKey:string, date?:Date, service?:string}} input
 */
export function signV4({ method, url, headers = {}, payloadSha256, region, accessKeyId, secretAccessKey, date = new Date(), service = 's3' }) {
  const amzDate = date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const day = amzDate.slice(0, 8);
  const all = { ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, ' ')])), host: url.host, 'x-amz-date': amzDate, 'x-amz-content-sha256': payloadSha256 };
  const names = Object.keys(all).sort();
  const canonicalQuery = [...url.searchParams.entries()].map(([k, v]) => [enc(k), enc(v)]).sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : a[0] < b[0] ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('&');
  const canonicalPath = url.pathname.split('/').map(segment => enc(decodeURIComponent(segment))).join('/');
  const canonical = [method, canonicalPath, canonicalQuery, names.map(n => `${n}:${all[n]}\n`).join(''), names.join(';'), payloadSha256].join('\n');
  const scope = `${day}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, day), region), service), 'aws4_request');
  const signature = createHmac('sha256', signingKey).update(toSign).digest('hex');
  return { ...all, authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` };
}

/** S3-compatible adapter (Backblaze B2). Path-style requests; bucket must be private. */
export function createS3Storage({ endpoint, region, bucket, accessKeyId, secretAccessKey }, { fetchImpl = fetch } = {}) {
  const base = new URL(endpoint);
  async function request(method, key, { query = {}, body = null, headers = {} } = {}) {
    const url = new URL(`${base.origin}/${bucket}${key ? `/${key}` : ''}`);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    const payload = body ?? Buffer.alloc(0);
    const signed = signV4({ method, url, headers, payloadSha256: sha256(payload), region, accessKeyId, secretAccessKey });
    delete signed.host;
    const response = await fetchImpl(url, { method, headers: signed, body: body ?? undefined, redirect: 'error' });
    if (!response.ok) {
      // Never surface provider bodies (they can echo keys or request details).
      await response.arrayBuffer().catch(() => {});
      throw new StorageError(response.status === 404 ? 'STORAGE_NOT_FOUND' : `STORAGE_HTTP_${response.status}`);
    }
    return response;
  }
  const tag = (xml, name) => new RegExp(`<${name}>([^<]+)</${name}>`).exec(xml)?.[1] ?? null;
  return {
    driver: 's3',
    async health() {
      const response = await request('GET', '', { query: { 'list-type': '2', 'max-keys': '0' } });
      await response.arrayBuffer();
      return { status: 'ok', detail: { driver: 's3' } };
    },
    async createMultipart(key) {
      assertKey(key);
      const xml = await (await request('POST', key, { query: { uploads: '' }, headers: { 'content-type': 'application/octet-stream' } })).text();
      const id = tag(xml, 'UploadId');
      if (!id) throw new StorageError('STORAGE_PROTOCOL');
      return id;
    },
    async uploadPart(key, uploadId, partNumber, bytes) {
      assertKey(key);
      const response = await request('PUT', key, { query: { partNumber: String(partNumber), uploadId }, body: Buffer.from(bytes) });
      await response.arrayBuffer();
      const etag = response.headers.get('etag');
      if (!etag) throw new StorageError('STORAGE_PROTOCOL');
      return etag;
    },
    async completeMultipart(key, uploadId, parts) {
      assertKey(key);
      const body = Buffer.from(`<CompleteMultipartUpload>${parts.map(p => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag.replace(/[<>&]/g, '')}</ETag></Part>`).join('')}</CompleteMultipartUpload>`);
      const xml = await (await request('POST', key, { query: { uploadId }, body, headers: { 'content-type': 'application/xml' } })).text();
      if (/<Error>/.test(xml)) throw new StorageError('STORAGE_COMPLETE_FAILED');
    },
    async abortMultipart(key, uploadId) { assertKey(key); await (await request('DELETE', key, { query: { uploadId } })).arrayBuffer(); },
    async *getObject(key) {
      assertKey(key);
      const response = await request('GET', key);
      for await (const chunk of response.body) yield Buffer.from(chunk);
    },
    async deleteObject(key) { assertKey(key); await (await request('DELETE', key)).arrayBuffer(); },
    async exists(key) { try { await (await request('HEAD', key)).arrayBuffer(); return true; } catch (e) { if (e.code === 'STORAGE_NOT_FOUND') return false; throw e; } },
  };
}

/** Build the configured adapter, or null when storage is not configured. */
export function selectStorage(objectStorage) {
  switch (objectStorage?.driver) {
    case 'memory': return createMemoryStorage();
    case 'filesystem': return createFilesystemStorage(objectStorage.directory);
    case 's3': return createS3Storage(objectStorage);
    default: return null;
  }
}

/** Stream an object through SHA-256, enforcing a byte ceiling. */
export async function digestObject(storage, key, { maxBytes }) {
  const hash = createHash('sha256');
  let size = 0;
  let head = Buffer.alloc(0);
  for await (const chunk of storage.getObject(key)) {
    size += chunk.length;
    if (size > maxBytes) throw new StorageError('STORAGE_OBJECT_TOO_LARGE');
    if (head.length < 4096) head = Buffer.concat([head, chunk.subarray(0, 4096 - head.length)]);
    hash.update(chunk);
  }
  return { sha256: hash.digest('hex'), size, head };
}
