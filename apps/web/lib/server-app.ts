import 'server-only';
import { createHeardServer, type HeardApp } from '@heard/server';

// One composition root per server process. Configuration was validated by the
// start script; any error here fails requests closed rather than serving partially.
let app: HeardApp | undefined;
export function getServerApp(): HeardApp {
  app ??= createHeardServer();
  return app;
}
