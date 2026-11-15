import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
export { migrate } from './migrate.mjs';
export { LATEST_MIGRATION, SCOPED_ROLES, isUuid, createPool, withTransaction, withScope, bindEnvironment, probeDatabase } from './runtime.mjs';
/** Canonical, checksum-bound migration directory shipped with the repository. */
export const migrationsDirectory = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'db', 'migrations');
