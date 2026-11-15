import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { detectType, inspectObject, createFakeScanner, createClamdScanner, createNoScanner, EICAR } from '../packages/quarantine/src/index.mjs';

async function* chunks(...parts) { for (const p of parts) yield Buffer.from(p); }
const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 16]);
const mp4 = Buffer.concat([Buffer.from([0, 0, 0, 24]), Buffer.from('ftypisom')]);

test('type detection uses magic bytes, never names or declarations', () => {
  assert.equal(detectType(png), 'image/png');
  assert.equal(detectType(jpeg), 'image/jpeg');
  assert.equal(detectType(Buffer.from('%PDF-1.7')), 'application/pdf');
  assert.equal(detectType(mp4), 'video/mp4');
  assert.equal(detectType(Buffer.concat([Buffer.from([0, 0, 0, 20]), Buffer.from('ftypqt  ')])), 'video/quicktime');
  assert.equal(detectType(Buffer.concat([Buffer.from([0, 0, 0, 20]), Buffer.from('ftypM4A ')])), 'audio/mp4');
  assert.equal(detectType(Buffer.from('ID3\x04')), 'audio/mpeg');
  for (const bad of [Buffer.from('MZ\x90\x00'), Buffer.from('PK\x03\x04'), Buffer.from('<html>'), Buffer.from('#!/bin/sh'), Buffer.alloc(0), Buffer.concat([Buffer.from([0, 0, 0, 20]), Buffer.from('ftypXXXX')])]) assert.equal(detectType(bad), null);
});

test('inspection computes digest and size and flags active PDF content, polyglots and oversize', async () => {
  const clean = await inspectObject(chunks('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj'), { maxBytes: 1000, declaredType: 'application/pdf' });
  assert.equal(clean.finding, null); assert.equal(clean.detectedType, 'application/pdf'); assert.match(clean.sha256, /^[a-f0-9]{64}$/);
  for (const marker of ['/JavaScript', '/Launch', '/EmbeddedFile', '/OpenAction << /S /JS', '/XFA']) {
    const split = Math.floor(marker.length / 2);
    const r = await inspectObject(chunks('%PDF-1.7\n<< ', marker.slice(0, split), marker.slice(split), ' >>'), { maxBytes: 1000, declaredType: 'application/pdf' });
    assert.equal(r.finding, 'pdf_active_content', `${marker} across a chunk boundary`);
  }
  assert.equal((await inspectObject(chunks(png, '<scr', 'ipt>alert(1)</script>'), { maxBytes: 1000, declaredType: 'image/png' })).finding, 'polyglot_marker');
  assert.equal((await inspectObject(chunks(jpeg, Buffer.from('%PDF-1.4')), { maxBytes: 1000, declaredType: 'image/jpeg' })).finding, 'polyglot_marker');
  assert.equal((await inspectObject(chunks(Buffer.alloc(2000)), { maxBytes: 1000, declaredType: 'image/png' })).finding, 'oversize');
});

test('fake scanner detects the EICAR test string across chunk boundaries; absent scanner never clears', async () => {
  const scanner = createFakeScanner();
  assert.equal((await scanner.scan(chunks(jpeg, 'harmless synthetic bytes'))).verdict, 'clean');
  assert.equal((await scanner.scan(chunks(jpeg, EICAR.slice(0, 20), EICAR.slice(20)))).verdict, 'infected');
  await assert.rejects(createNoScanner().scan(chunks('x')), { code: 'SCANNER_UNAVAILABLE' });
  await assert.rejects(createFakeScanner({ fail: true }).scan(chunks('x')), { code: 'SCANNER_ERROR' });
});

test('clamd INSTREAM adapter: framing, verdicts, errors, timeouts and unavailability', async () => {
  let mode = 'ok';
  const received = [];
  const server = createServer(socket => {
    let data = Buffer.alloc(0);
    socket.on('data', d => {
      data = Buffer.concat([data, d]);
      if (data.toString('latin1').startsWith('zPING\0')) { socket.end('PONG\0'); return; }
      if (!data.toString('latin1').startsWith('zINSTREAM\0')) return;
      let offset = 10; const body = [];
      while (offset + 4 <= data.length) {
        const len = data.readUInt32BE(offset);
        if (len === 0) {
          received.push(Buffer.concat(body));
          if (mode === 'hang') return;
          const content = Buffer.concat(body).toString('latin1');
          socket.end(mode === 'error' ? 'INSTREAM size limit exceeded. ERROR\0' : content.includes(EICAR) ? 'stream: Eicar-Signature FOUND\0' : 'stream: OK\0');
          return;
        }
        if (offset + 4 + len > data.length) return;
        body.push(data.subarray(offset + 4, offset + 4 + len)); offset += 4 + len;
      }
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const clamd = createClamdScanner({ host: '127.0.0.1', port, timeoutMs: 500 });
    assert.equal((await clamd.health()).status, 'ok');
    const big = Buffer.alloc(200_000, 7);
    assert.deepEqual(await clamd.scan(chunks(big)), { verdict: 'clean', engine: 'clamav-clamd' });
    assert.ok(received.at(-1).equals(big), 'bytes framed and reassembled exactly');
    assert.equal((await clamd.scan(chunks(EICAR))).verdict, 'infected');
    mode = 'error';
    await assert.rejects(clamd.scan(chunks('x')), { code: 'SCANNER_ERROR' });
    mode = 'hang';
    await assert.rejects(clamd.scan(chunks('x')), { code: 'SCAN_TIMEOUT' });
  } finally { await new Promise(r => server.close(r)); }
  await assert.rejects(createClamdScanner({ host: '127.0.0.1', port, timeoutMs: 500 }).scan(chunks('x')), { code: 'SCANNER_UNAVAILABLE' });
});
