import pg from 'pg';
import { loadConfig } from '../packages/config/src/index.mjs';
import { migrate, bindEnvironment, migrationsDirectory } from '../packages/database/src/index.mjs';

/** Apply checksum-bound migrations and bind the database to HEARD_ENV. */
export async function migrateConfigured(config) {
  if (!config.database) throw new Error('DATABASE_URL is required; never use a production connection for fixture tests.');
  const client = new pg.Client({ connectionString: config.database.url, application_name: 'heard-migrate' });
  await client.connect();
  try {
    const applied = await migrate(client, migrationsDirectory);
    const environment = await bindEnvironment(client, config.environment);
    return { applied, environment };
  } finally { await client.end(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await migrateConfigured(loadConfig(process.env));
  console.log(JSON.stringify(result));
}
