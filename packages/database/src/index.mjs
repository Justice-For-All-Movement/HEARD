export { migrate } from './migrate.mjs';
/** Canonical, checksum-bound migration directory shipped with the repository. */
export const migrationsDirectory = new URL('../../../db/migrations/', import.meta.url);
