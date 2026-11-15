import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomUUID } from 'node:crypto';
import { startPostgres } from '../database/postgres-fixture.mjs';
import { migrate, migrationsDirectory, bindEnvironment, withTransaction } from '../../packages/database/src/index.mjs';
import { createLocalAdapter } from '../../packages/secure-intake/src/index.mjs';
import { loadConfig } from '../../packages/config/src/index.mjs';
import { createHeardServer } from '../../packages/server/src/index.mjs';

const silent = { debug() {}, info() {}, warn() {}, error() {} };

test('local Secure Intake adapter contract on native PostgreSQL', async t => {
  const server = await startPostgres();
  const admin = await server.database('heard_test_adapter');
  const pool = new pg.Pool({ ...server.connection('heard_test_adapter'), max: 4 });
  const adapter = createLocalAdapter();
  try {
    await migrate(admin, migrationsDirectory);
    await bindEnvironment(admin, 'ci');
    const subject = randomUUID();
    await admin.query('INSERT INTO heard_subjects(id) VALUES($1)', [subject]);

    await t.test('draft → submitted records minimal events and replays conflict', async () => {
      const caseId = randomUUID();
      await withTransaction(pool, c => adapter.createDraft(c, { caseId, subjectId: subject, kind: 'experience' }));
      assert.equal((await withTransaction(pool, c => adapter.readStatus(c, { caseId }))).status, 'draft');
      await withTransaction(pool, c => adapter.submit(c, { caseId, actorId: subject, policyVersion: 'processing-v1' }));
      await assert.rejects(withTransaction(pool, c => adapter.submit(c, { caseId, actorId: subject, policyVersion: 'processing-v1' })), { code: 'ADAPTER_STATE_CONFLICT' });
      const events = (await admin.query('SELECT event_type, event_metadata FROM heard_case_events WHERE case_id=$1 ORDER BY recorded_at, event_type', [caseId])).rows;
      assert.deepEqual(events.map(e => e.event_type).sort(), ['case_created', 'case_submitted']);
      assert.deepEqual(events.find(e => e.event_type === 'case_submitted').event_metadata, { policyVersion: 'processing-v1' });
    });

    await t.test('concurrent submissions: exactly one wins', async () => {
      const caseId = randomUUID();
      await withTransaction(pool, c => adapter.createDraft(c, { caseId, subjectId: subject, kind: 'question' }));
      const results = await Promise.allSettled([1, 2, 3].map(() => withTransaction(pool, c => adapter.submit(c, { caseId, actorId: subject, policyVersion: 'processing-v1' }))));
      assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
      assert.ok(results.filter(r => r.status === 'rejected').every(r => r.reason.code === 'ADAPTER_STATE_CONFLICT'));
    });

    await t.test('withdrawal is terminal; invalid transitions and kinds are rejected', async () => {
      const caseId = randomUUID();
      await withTransaction(pool, c => adapter.createDraft(c, { caseId, subjectId: subject, kind: 'support' }));
      await withTransaction(pool, c => adapter.withdraw(c, { caseId, actorId: subject }));
      await assert.rejects(withTransaction(pool, c => adapter.submit(c, { caseId, actorId: subject, policyVersion: 'v' })), { code: 'ADAPTER_STATE_CONFLICT' });
      await assert.rejects(withTransaction(pool, c => adapter.withdraw(c, { caseId, actorId: subject })), { code: 'ADAPTER_INVALID_TRANSITION' });
      await assert.rejects(withTransaction(pool, c => adapter.startReview(c, { caseId, actorId: subject })), { code: 'ADAPTER_STATE_CONFLICT' });
      await assert.rejects(withTransaction(pool, c => adapter.createDraft(c, { caseId: randomUUID(), subjectId: subject, kind: 'publication' })), { code: 'ADAPTER_INVALID_REQUEST' });
    });

    await t.test('unknown cases and malformed IDs are indistinguishable not-found / invalid', async () => {
      await assert.rejects(withTransaction(pool, c => adapter.readStatus(c, { caseId: randomUUID() })), { code: 'ADAPTER_NOT_FOUND' });
      await assert.rejects(withTransaction(pool, c => adapter.readStatus(c, { caseId: "1' OR '1'='1" })), { code: 'ADAPTER_INVALID_REQUEST' });
    });

    await t.test('a failed event write rolls back the state change', async () => {
      const caseId = randomUUID();
      await withTransaction(pool, c => adapter.createDraft(c, { caseId, subjectId: subject, kind: 'question' }));
      await assert.rejects(withTransaction(pool, async c => {
        await adapter.submit(c, { caseId, actorId: subject, policyVersion: 'v1' });
        await adapter.recordEvent(c, { caseId, type: 'info_requested', metadata: { narrative: 'x' } });
      }), { code: 'ADAPTER_UNSAFE_METADATA' });
      assert.equal((await withTransaction(pool, c => adapter.readStatus(c, { caseId }))).status, 'draft');
    });

    await t.test('readiness requires a verified engine only when intake is enabled', async () => {
      const remoteOff = createHeardServer({ config: loadConfig({ HEARD_ENV: 'ci', DATABASE_URL: 'postgres://f@localhost/x', HEARD_SECURE_INTAKE_MODE: 'remote', HEARD_SECURE_INTAKE_URL: 'https://engine.example.invalid', HEARD_SECURE_INTAKE_API_VERSION: 'v1', HEARD_SECURE_INTAKE_TOKEN: 'x' }), pool, logger: silent });
      assert.equal((await remoteOff.handle(new Request('http://h/api/ready'))).status, 200, 'remote engine is optional while intake is disabled');
      const key = n => Buffer.alloc(32, n).toString('base64');
      const remoteOn = createHeardServer({ config: loadConfig({ HEARD_ENV: 'ci', DATABASE_URL: 'postgres://f@localhost/x', HEARD_INTAKE_ENABLED: 'true', HEARD_SESSION_SECRET: key(1), HEARD_DATA_ENCRYPTION_KEY: key(2), HEARD_SECURE_INTAKE_MODE: 'remote', HEARD_SECURE_INTAKE_URL: 'https://engine.example.invalid', HEARD_SECURE_INTAKE_API_VERSION: 'v1', HEARD_SECURE_INTAKE_TOKEN: 'x' }), pool, logger: silent });
      assert.equal((await remoteOn.handle(new Request('http://h/api/ready'))).status, 503, 'unverified engine blocks readiness when intake is on');
      const localOn = createHeardServer({ config: loadConfig({ HEARD_ENV: 'ci', DATABASE_URL: 'postgres://f@localhost/x', HEARD_INTAKE_ENABLED: 'true', HEARD_SESSION_SECRET: key(1), HEARD_DATA_ENCRYPTION_KEY: key(2) }), pool, logger: silent });
      assert.equal((await localOn.handle(new Request('http://h/api/ready'))).status, 200);
    });
  } finally {
    await pool.end();
    await admin.end();
    await server.stop();
  }
});
