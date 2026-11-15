import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CASE_TRANSITIONS, CASE_STATES, canTransition, sanitizeEventMetadata, createRemoteAdapter, createLocalAdapter, selectAdapter, requireCapability, VERIFIED_UPSTREAM_VERSIONS, CAPABILITIES } from '../packages/secure-intake/src/index.mjs';

test('case state machine only allows forward transitions and terminal states are final', () => {
  for (const state of CASE_STATES) assert.ok(Object.hasOwn(CASE_TRANSITIONS, state));
  assert.equal(canTransition('draft', 'submitted'), true);
  assert.equal(canTransition('submitted', 'draft'), false);
  assert.equal(canTransition('closed', 'review'), false);
  assert.equal(canTransition('withdrawn', 'submitted'), false);
  assert.equal(canTransition('__proto__', 'draft'), false);
  assert.equal(canTransition('draft', 'published'), false);
});

test('event metadata rejects narrative, contact data and unknown keys', () => {
  assert.deepEqual(sanitizeEventMetadata({ policyVersion: 'processing-2026-11', channel: 'web' }), { policyVersion: 'processing-2026-11', channel: 'web' });
  assert.throws(() => sanitizeEventMetadata({ narrative: 'what happened' }), { code: 'ADAPTER_UNSAFE_METADATA' });
  assert.throws(() => sanitizeEventMetadata({ reason: 'contains spaces and a story' }), { code: 'ADAPTER_UNSAFE_METADATA' });
  assert.throws(() => sanitizeEventMetadata({ reason: 'person@example.org' }), { code: 'ADAPTER_UNSAFE_METADATA' });
  assert.throws(() => sanitizeEventMetadata([]), { code: 'ADAPTER_INVALID_REQUEST' });
});

test('remote adapter is unavailable until an upstream version is verified, and makes no network call', async () => {
  assert.equal(VERIFIED_UPSTREAM_VERSIONS.length, 0, 'no upstream contract has been verified; update the manifest with evidence first');
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('network'); };
  try {
    const remote = selectAdapter({ mode: 'remote', url: 'https://engine.example.invalid', apiVersion: 'v1', token: 't' });
    assert.equal(remote.id, 'remote');
    assert.deepEqual(await remote.health(), { status: 'fail', detail: { code: 'UPSTREAM_CONTRACT_UNVERIFIED', mode: 'remote' } });
    await assert.rejects(remote.submit({}, {}), { code: 'UPSTREAM_CONTRACT_UNVERIFIED' });
    assert.throws(() => requireCapability(remote, 'case.submit'), { code: 'ADAPTER_CAPABILITY_UNSUPPORTED' });
    const pretendVerified = createRemoteAdapter({ apiVersion: 'v1' }, { verifiedVersions: ['v1'] });
    await assert.rejects(pretendVerified.readStatus({}, {}), { code: 'ADAPTER_NOT_IMPLEMENTED' });
    assert.equal(called, false);
  } finally { globalThis.fetch = original; }
});

test('local adapter declares only what it implements; unknown modes fail', () => {
  const local = createLocalAdapter();
  requireCapability(local, 'case.submit');
  assert.throws(() => requireCapability(local, 'case.helper_grant'), { code: 'ADAPTER_CAPABILITY_UNSUPPORTED' });
  assert.throws(() => requireCapability(local, 'case.teleport'), { code: 'ADAPTER_UNKNOWN_CAPABILITY' });
  assert.throws(() => selectAdapter({ mode: 'fallback' }), { code: 'ADAPTER_MODE_INVALID' });
});

test('compatibility manifest matches the implementation', () => {
  const manifest = JSON.parse(readFileSync('contracts/secure-intake-boundary.v1.json', 'utf8'));
  assert.deepEqual(manifest.adapters.local.capabilities, [...createLocalAdapter().capabilities]);
  assert.deepEqual(manifest.adapters.remote.verifiedUpstreamVersions, [...VERIFIED_UPSTREAM_VERSIONS]);
  assert.deepEqual([...manifest.adapters.local.capabilities, ...manifest.unsupportedCapabilities].sort(), [...CAPABILITIES].sort());
  assert.equal(manifest.liveConnectionVerified, false);
});
