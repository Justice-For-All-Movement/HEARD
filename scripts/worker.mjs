/**
 * HEARD background worker (HEARD-13 scanning, HEARD-11 draft expiry, HEARD-12 upload expiry).
 * Runs as a separate process (Render background worker) with the same configuration
 * as the web service; it drops to the heard_job_worker role for every transaction.
 *   npm run worker            # loop
 *   npm run worker -- --once  # single pass (cron / tests)
 */
import { randomUUID } from 'node:crypto';
import { loadConfig, ConfigError } from '../packages/config/src/index.mjs';
import { createPool } from '../packages/database/src/index.mjs';
import { createLogger, errorCode } from '../packages/operations/src/index.mjs';
import { purgeExpiredDrafts } from '../packages/drafts/src/index.mjs';
import { expireUploadSessions } from '../packages/uploads/src/index.mjs';
import { processScanJobs, selectScanner } from '../packages/quarantine/src/index.mjs';
import { selectStorage } from '../packages/storage/src/index.mjs';

export async function runOnce({ pool, storage, scanner, workerId, logger }) {
  const drafts = await purgeExpiredDrafts(pool);
  const uploads = storage ? await expireUploadSessions(pool, storage) : 0;
  const scans = storage ? await processScanJobs(pool, { storage, scanner, workerId }) : [];
  if (drafts || uploads || scans.length) logger.info('worker_pass', { count: drafts + uploads + scans.length, state: scans.map(s => s.state).join(' ') || 'none' });
  return { drafts, uploads, scans };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let config;
  try { config = loadConfig(process.env); } catch (error) {
    if (error instanceof ConfigError) { process.stderr.write(`${JSON.stringify({ level: 'error', event: 'config_invalid', problems: error.problems })}\n`); process.exit(78); }
    throw error;
  }
  const logger = createLogger({ level: config.logLevel, base: { component: 'worker', environment: config.environment } });
  if (!config.database) { logger.error('worker_requires_database'); process.exit(78); }
  const pool = createPool(config.database);
  const storage = selectStorage(config.objectStorage);
  const scanner = selectScanner(config.scanner);
  const workerId = randomUUID();
  let stopping = false;
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; });
  logger.info('worker_started', { driver: config.objectStorage.driver, mode: config.scanner.driver });
  do {
    try { await runOnce({ pool, storage, scanner, workerId, logger }); }
    catch (error) { logger.error('worker_pass_failed', { code: errorCode(error) }); }
    if (process.argv.includes('--once')) break;
    for (let i = 0; i < 30 && !stopping; i++) await new Promise(r => setTimeout(r, 1000));
  } while (!stopping);
  await pool.end();
  logger.info('worker_stopped');
}
