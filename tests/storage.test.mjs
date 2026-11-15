import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signV4, EMPTY_SHA256, createMemoryStorage, createFilesystemStorage, createS3Storage, quarantineKey, digestObject, assertKey } from '../packages/storage/src/index.mjs';

const sha = b => createHash('sha256').update(b).digest('hex');

test('SigV4 signer reproduces the AWS S3 documented GET Object example', () => {
  const headers = signV4({
    method: 'GET', url: new URL('https://examplebucket.s3.amazonaws.com/test.txt'), headers: { Range: 'bytes=0-9' },
    payloadSha256: EMPTY_SHA256, region: 'us-east-1', date: new Date('2013-05-24T00:00:00Z'),
    accessKeyId: ['AKIAIOSFODNN7', 'EXAMPLE'].join(''), secretAccessKey: ['wJalrXUtnFEMI/K7MDENG/bPxRfiCY', 'EXAMPLEKEY'].join(''),
  });
  assert.match(headers.authorization, /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41$/);
});

test('keys are opaque server identifiers; traversal and user text are rejected', () => {
  assertKey(quarantineKey());
  for (const bad of ['../etc/passwd', 'quarantine/../../x', 'quarantine/my-photo.jpg', 'public/00000000-0000-4000-8000-000000000000', '']) assert.throws(() => assertKey(bad), { code: 'STORAGE_KEY_INVALID' });
});

async function exerciseMultipart(storage) {
  const key = quarantineKey();
  const a = Buffer.alloc(70_000, 1); const b = Buffer.from('tail bytes');
  const id = await storage.createMultipart(key);
  const etagB = await storage.uploadPart(key, id, 2, b);
  const etagA = await storage.uploadPart(key, id, 1, a);
  await assert.rejects(storage.completeMultipart(key, id, [{ partNumber: 1, etag: etagA }, { partNumber: 2, etag: '"wrong"' }]), /PART_MISMATCH|COMPLETE|HTTP/);
  await storage.completeMultipart(key, id, [{ partNumber: 1, etag: etagA }, { partNumber: 2, etag: etagB }]);
  const digest = await digestObject(storage, key, { maxBytes: 1_000_000 });
  assert.equal(digest.sha256, sha(Buffer.concat([a, b])));
  assert.equal(digest.size, a.length + b.length);
  await assert.rejects(digestObject(storage, key, { maxBytes: 10 }), { code: 'STORAGE_OBJECT_TOO_LARGE' });
  assert.equal(await storage.exists(key), true);
  await storage.deleteObject(key);
  assert.equal(await storage.exists(key), false);
  await assert.rejects(storage.uploadPart(key, '00000000-0000-4000-8000-000000000000', 1, a), { code: /STORAGE_UPLOAD_UNKNOWN|STORAGE_HTTP_404|STORAGE_NOT_FOUND/ });
}

test('memory adapter multipart semantics', () => exerciseMultipart(createMemoryStorage()));

test('filesystem adapter multipart semantics with private permissions', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'heard-store-'));
  try {
    const storage = createFilesystemStorage(join(dir, 'objects'));
    assert.equal((await storage.health()).status, 'ok');
    assert.equal(statSync(join(dir, 'objects')).mode & 0o077, 0, 'directory not group/world accessible');
    await exerciseMultipart(storage);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('S3 adapter signs every request, uses path-style keys and never surfaces provider bodies', async () => {
  const objects = new Map(); const uploads = new Map(); const seen = [];
  const fakeFetch = async (url, init) => {
    seen.push({ url: String(url), method: init.method, auth: init.headers.authorization });
    assert.match(init.headers.authorization, /^AWS4-HMAC-SHA256 Credential=test-key\/\d{8}\/us-west-004\/s3\/aws4_request/);
    assert.equal(init.headers['x-amz-content-sha256'], sha(init.body ?? Buffer.alloc(0)));
    const u = new URL(url); const key = u.pathname.split('/').slice(2).join('/');
    assert.equal(u.pathname.split('/')[1], 'heard-private');
    if (init.method === 'GET' && !key) return new Response('<ListBucketResult/>');
    if (init.method === 'POST' && u.searchParams.has('uploads')) { const id = `up-${uploads.size}`; uploads.set(id, new Map()); return new Response(`<InitiateMultipartUploadResult><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`); }
    if (init.method === 'PUT' && u.searchParams.has('partNumber')) { const parts = uploads.get(u.searchParams.get('uploadId')); if (!parts) return new Response('<Error>NoSuchUpload secret-detail</Error>', { status: 404 }); parts.set(Number(u.searchParams.get('partNumber')), Buffer.from(init.body)); return new Response('', { headers: { etag: `"${sha(init.body)}"` } }); }
    if (init.method === 'POST' && u.searchParams.has('uploadId')) {
      const parts = uploads.get(u.searchParams.get('uploadId'));
      const listed = [...String(init.body).matchAll(/<PartNumber>(\d+)<\/PartNumber><ETag>"([a-f0-9]+|wrong)"<\/ETag>/g)];
      if (listed.some(([, n, e]) => sha(parts.get(Number(n)) ?? '') !== e)) return new Response('<Error><Code>InvalidPart</Code></Error>', { status: 400 });
      objects.set(key, Buffer.concat(listed.map(([, n]) => parts.get(Number(n))))); return new Response('<CompleteMultipartUploadResult/>');
    }
    if (init.method === 'GET') return objects.has(key) ? new Response(objects.get(key)) : new Response('<Error>NoSuchKey internal-path</Error>', { status: 404 });
    if (init.method === 'HEAD') return objects.has(key) ? new Response(null) : new Response(null, { status: 404 });
    if (init.method === 'DELETE') { objects.delete(key); uploads.delete(u.searchParams.get('uploadId')); return new Response(null, { status: 204 }); }
    return new Response('unexpected', { status: 500 });
  };
  const storage = createS3Storage({ endpoint: 'https://s3.us-west-004.backblazeb2.com', region: 'us-west-004', bucket: 'heard-private', accessKeyId: 'test-key', secretAccessKey: 'test-secret-value' }, { fetchImpl: fakeFetch });
  assert.equal((await storage.health()).status, 'ok');
  await exerciseMultipart(storage);
  try { await storage.getObject('quarantine/00000000-0000-4000-8000-000000000000').next(); assert.fail(); }
  catch (error) { assert.equal(error.code, 'STORAGE_NOT_FOUND'); assert.doesNotMatch(error.message, /internal-path/); }
  assert.ok(seen.every(r => r.url.startsWith('https://s3.us-west-004.backblazeb2.com/heard-private')));
  assert.ok(seen.every(r => !r.auth.includes('test-secret-value')));
});
