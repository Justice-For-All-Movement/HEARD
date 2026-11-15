/**
 * Production entry point (Render start command). Validates configuration before
 * listening, optionally applies migrations, then serves the Next.js app.
 * Invalid configuration exits non-zero with variable names only, never values.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadConfig, describeConfig, ConfigError } from '../packages/config/src/index.mjs';
import { createLogger, errorCode } from '../packages/operations/src/index.mjs';
import { migrateConfigured } from './migrate.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
let config;
try {
  config = loadConfig(process.env);
} catch (error) {
  if (error instanceof ConfigError) {
    process.stderr.write(`${JSON.stringify({ level: 'error', event: 'config_invalid', problems: error.problems })}\n`);
    process.exit(78);
  }
  throw error;
}
const logger = createLogger({ level: config.logLevel, base: { component: 'start', environment: config.environment } });
logger.info('config_loaded', { release: config.release ?? 'unknown', status: config.intake.enabled ? 'intake_enabled' : 'intake_disabled', mode: config.secureIntake.mode, driver: config.objectStorage.driver });

if (config.database?.migrateOnStart) {
  try {
    const { applied } = await migrateConfigured(config);
    logger.info('migrations_applied', { applied });
  } catch (error) {
    logger.error('migrations_failed', { code: errorCode(error) });
    process.exit(1);
  }
}

const next = join(root, 'node_modules', 'next', 'dist', 'bin', 'next');
const child = spawn(process.execPath, [next, 'start', join(root, 'apps', 'web'), '-p', String(config.port), '-H', '0.0.0.0'], {
  stdio: 'inherit',
  env: { ...process.env, HEARD_ENV: config.environment, NEXT_TELEMETRY_DISABLED: '1' },
});
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
child.on('exit', (code, signal) => process.exit(signal ? 1 : (code ?? 1)));
