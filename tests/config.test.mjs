import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { loadConfig, describeConfig, ConfigError, VARIABLES } from '../packages/config/src/index.mjs';
import { LATEST_MIGRATION } from '../packages/database/src/runtime.mjs';

const key = n => Buffer.alloc(32, n).toString('base64');
const intake = { HEARD_INTAKE_ENABLED: 'true', DATABASE_URL: 'postgres://heard@localhost/heard', HEARD_SESSION_SECRET: key(1), HEARD_DATA_ENCRYPTION_KEY: key(2) };

test('defaults run the public shell with no external credentials', () => {
  const config = loadConfig({});
  assert.equal(config.environment, 'local');
  assert.equal(config.database, null);
  assert.equal(config.intake.enabled, false);
  assert.equal(config.objectStorage.driver, 'none');
  assert.equal(config.scanner.driver, 'none');
  assert.equal(config.secureIntake.mode, 'local');
  assert.ok(Object.isFrozen(config) && Object.isFrozen(config.intake));
});

test('NODE_ENV=production defaults to the strict production environment', () => {
  assert.equal(loadConfig({ NODE_ENV: 'production' }).environment, 'production');
});

test('intake cannot be enabled without database, both keys and a public origin when deployed', () => {
  assert.throws(() => loadConfig({ HEARD_INTAKE_ENABLED: 'true' }), e => e instanceof ConfigError && e.problems.length === 3);
  assert.equal(loadConfig(intake).intake.enabled, true);
  assert.throws(() => loadConfig({ ...intake, HEARD_ENV: 'production', DATABASE_URL: 'postgres://h@db.example.invalid/x?sslmode=require' }), /HEARD_PUBLIC_ORIGIN/);
  const ok = loadConfig({ ...intake, HEARD_ENV: 'production', DATABASE_URL: 'postgres://h@db.example.invalid/x?sslmode=require', HEARD_PUBLIC_ORIGIN: 'https://heard.example.org' });
  assert.equal(ok.publicOrigin, 'https://heard.example.org');
});

test('secrets are validated for length, distinctness and never echoed', () => {
  assert.throws(() => loadConfig({ ...intake, HEARD_SESSION_SECRET: 'short' }), /at least 32/);
  assert.throws(() => loadConfig({ ...intake, HEARD_DATA_ENCRYPTION_KEY: Buffer.alloc(31).toString('base64') }), /exactly 32/);
  assert.throws(() => loadConfig({ ...intake, HEARD_DATA_ENCRYPTION_KEY: intake.HEARD_SESSION_SECRET }), /must be different/);
  try { loadConfig({ DATABASE_URL: ['mysql://user', 'topsecretvalue@h/x'].join(':') }); assert.fail('expected error'); }
  catch (error) { assert.doesNotMatch(error.message, /topsecretvalue/); }
  const summary = JSON.stringify(describeConfig(loadConfig(intake)));
  assert.doesNotMatch(summary, /localhost\/heard|AQEB/);
});

test('deployed environments require TLS to the database and forbid test-only drivers', () => {
  assert.throws(() => loadConfig({ HEARD_ENV: 'staging', DATABASE_URL: 'postgres://h@db.example.invalid/x' }), /sslmode/);
  assert.throws(() => loadConfig({ HEARD_ENV: 'production', HEARD_OBJECT_STORAGE_DRIVER: 'memory' }), /only for local/);
  assert.throws(() => loadConfig({ HEARD_ENV: 'production', HEARD_SCANNER_DRIVER: 'fake' }), /only for local/);
  assert.throws(() => loadConfig({ HEARD_ENV: 'production', HEARD_PUBLIC_ORIGIN: 'http://heard.example.org' }), /https/);
});

test('remote Secure Intake and S3 storage require every documented setting', () => {
  assert.throws(() => loadConfig({ HEARD_SECURE_INTAKE_MODE: 'remote' }), e => e.problems.length === 3);
  assert.throws(() => loadConfig({ HEARD_OBJECT_STORAGE_DRIVER: 's3' }), e => e.problems.length === 5);
  assert.throws(() => loadConfig({ HEARD_SECURE_INTAKE_MODE: 'remote', HEARD_SECURE_INTAKE_URL: 'https://user:pw@engine.example.invalid', HEARD_SECURE_INTAKE_API_VERSION: 'v1', HEARD_SECURE_INTAKE_TOKEN: 't' }), /credentials/);
});

test('malformed booleans and enumerations fail instead of defaulting', () => {
  assert.throws(() => loadConfig({ HEARD_INTAKE_ENABLED: 'maybe' }), /true or false/);
  assert.throws(() => loadConfig({ HEARD_ENV: 'prod' }), /HEARD_ENV/);
  assert.equal(loadConfig({ HEARD_MIGRATE_ON_START: 'true' }).database, null, 'migrate-on-start is inert without a database');
  assert.throws(() => loadConfig({ HEARD_MIGRATE_ON_START: 'sometimes' }), /true or false/);
});

test('every configuration variable is documented in .env.example, render.yaml and the deployment guide', () => {
  const example = readFileSync('.env.example', 'utf8');
  const guide = readFileSync('docs/DEPLOYMENT_RENDER.md', 'utf8');
  const blueprint = readFileSync('render.yaml', 'utf8');
  for (const [name, doc] of Object.entries(VARIABLES)) {
    if (name !== 'PORT') assert.match(example, new RegExp(`^#? ?${name}=`, 'm'), `${name} missing from .env.example`);
    assert.ok(guide.includes(`\`${name}\``), `${name} missing from deployment guide`);
    if (doc.secret) assert.doesNotMatch(example, new RegExp(`^${name}=\\S`, 'm'), `${name} must not have an example value`);
  }
  for (const match of blueprint.matchAll(/- key: (\w+)\n\s+sync: false/g)) assert.ok(VARIABLES[match[1]]?.secret, `${match[1]} sync:false only for secrets`);
  for (const [name, doc] of Object.entries(VARIABLES)) if (doc.secret && blueprint.includes(`key: ${name}`)) assert.match(blueprint, new RegExp(`key: ${name}\\n\\s+sync: false`), `${name} must be sync:false`);
});

test('runtime migration constant matches the shipped migration files', () => {
  assert.equal(readdirSync('db/migrations').filter(n => /^\d{4}_.*\.sql$/.test(n)).length, LATEST_MIGRATION);
});
