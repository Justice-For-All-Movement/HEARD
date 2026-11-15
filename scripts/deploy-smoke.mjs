/**
 * Deployability smoke test (CI): start the built service exactly as Render does
 * (`npm start`) and require /api/health to be alive and /api/ready to be ready.
 * Usage: node scripts/deploy-smoke.mjs   (environment supplies HEARD_ENV, DATABASE_URL, ...)
 */
import { spawn } from 'node:child_process';

const port = process.env.PORT ?? '3107';
// CI passes the throwaway database as parts so no connection string appears in source.
if (!process.env.DATABASE_URL && process.env.SMOKE_DB_USER) {
  const { SMOKE_DB_USER: user, SMOKE_DB_PASSWORD: password = '', SMOKE_DB_HOST: host = 'localhost', SMOKE_DB_NAME: name } = process.env;
  process.env.DATABASE_URL = `postgres://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:5432/${name}`;
}
const child = spawn('npm', ['start'], { env: { ...process.env, PORT: port }, stdio: ['ignore', 'inherit', 'inherit'], detached: true });
const base = `http://127.0.0.1:${port}`;
const deadline = Date.now() + 90_000;
let ok = false;
try {
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const health = await fetch(`${base}/api/health`);
      if (health.ok) {
        const ready = await fetch(`${base}/api/ready`);
        const body = await ready.json();
        console.log(JSON.stringify({ health: health.status, ready: ready.status, body }));
        ok = ready.status === 200 && body.status === 'ready';
        break;
      }
    } catch { /* not listening yet */ }
    await new Promise(r => setTimeout(r, 500));
  }
} finally {
  // npm does not always forward signals: stop the whole process group.
  try { process.kill(-child.pid, 'SIGTERM'); } catch { /* already gone */ }
}
if (!ok) { console.error('Deploy smoke test failed'); process.exit(1); }
console.log('Deploy smoke test passed');
