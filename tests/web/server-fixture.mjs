import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Start the built production server through the real start script on a free port.
 * Requires `npm run build` first; fails rather than skipping when the build is absent.
 */
export async function startWebServer(env = {}) {
  if (!existsSync(resolve('apps/web/.next/BUILD_ID'))) throw new Error('Run `npm run build` before web server tests.');
  for (let attempt = 0; attempt < 5; attempt++) {
    const port = 40000 + Math.floor(Math.random() * 20000);
    const child = spawn(process.execPath, ['scripts/start.mjs'], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, HEARD_ENV: 'ci', ...env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });
    const base = `http://127.0.0.1:${port}`;
    const ready = await new Promise(resolveReady => {
      const deadline = Date.now() + 30000;
      const poll = async () => {
        if (child.exitCode !== null) return resolveReady(false);
        try { if ((await fetch(`${base}/api/health`)).ok) return resolveReady(true); } catch { /* not listening yet */ }
        if (Date.now() > deadline) return resolveReady(false);
        setTimeout(poll, 150);
      };
      poll();
    });
    if (ready) {
      return {
        base,
        output: () => output,
        fetch: (path, init) => fetch(base + path, { redirect: 'manual', ...init }),
        stop: () => new Promise(done => { if (child.exitCode !== null) return done(); child.once('exit', done); child.kill('SIGTERM'); }),
      };
    }
    child.kill('SIGKILL');
    if (!/EADDRINUSE/.test(output)) throw new Error(`Web server failed to start: ${output.slice(-2000)}`);
  }
  throw new Error('No free port for web server test');
}

/** Run the start script expecting it to refuse to start. */
export function startExpectingFailure(env) {
  return new Promise(done => {
    const child = spawn(process.execPath, ['scripts/start.mjs'], { env: { PATH: process.env.PATH, ...env, PORT: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', c => { output += c; });
    child.stderr.on('data', c => { output += c; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
    child.on('exit', code => { clearTimeout(timer); done({ code, output }); });
  });
}
