/**
 * HEARD API composition root. Framework-agnostic: takes a WHATWG Request and
 * returns a Response, so the same handlers run under Next.js route handlers and
 * directly in integration tests against real PostgreSQL.
 */
import { loadConfig, describeConfig } from '@heard/config';
import { createPool, probeDatabase } from '@heard/database';
import { assessReadiness, createLogger, errorCode, liveness, operatorAuthorized, publicReadiness } from '@heard/operations';
import { adapterReadinessCheck, selectAdapter } from '@heard/secure-intake';
import { HttpError, errorResponse, json } from './http.mjs';
import { identityModule } from './identity-routes.mjs';
import { consentModule } from './consent-routes.mjs';
import { draftsModule } from './drafts-routes.mjs';

export { HttpError, errorResponse, json } from './http.mjs';

/**
 * @param {{config?: import('@heard/config').HeardConfig, env?: Record<string,string|undefined>, pool?: any, logger?: any, extraChecks?: any[]}} options
 */
export function createApp(options = {}) {
  const config = options.config ?? loadConfig(options.env ?? process.env);
  const logger = options.logger ?? createLogger({ level: config.logLevel, base: { component: 'api', environment: config.environment } });
  let pool = options.pool ?? null;
  const ownsPool = !options.pool;
  const getPool = () => {
    if (!config.database) throw new HttpError('SERVICE_UNAVAILABLE');
    pool ??= createPool(config.database);
    return pool;
  };

  const context = { config, logger, getPool, modules: [] };

  const routes = [
    { method: 'GET', pattern: /^\/api\/health$/, handler: () => json(200, liveness({ release: config.release })) },
    { method: 'GET', pattern: /^\/api\/ready$/, handler: request => readiness(request) },
  ];

  /** Readiness checks: database is required whenever configured or when intake is enabled. */
  function checks() {
    const list = [{
      name: 'database',
      required: Boolean(config.database) || config.intake.enabled,
      probe: async () => config.database ? probeDatabase(getPool(), { environment: config.environment }) : { status: 'not_configured' },
    }];
    for (const module of context.modules) list.push(...(module.readinessChecks?.() ?? []));
    for (const check of options.extraChecks ?? []) list.push(check);
    return list;
  }

  async function readiness(request) {
    const assessment = await assessReadiness(checks());
    const url = new URL(request.url);
    const status = assessment.ready ? 200 : 503;
    if (url.searchParams.get('detail') === '1') {
      if (!operatorAuthorized(request.headers.get('authorization'), config.operationsToken)) return errorResponse('NOT_FOUND');
      return json(status, { ...publicReadiness(assessment), components: assessment.components, config: describeConfig(config) });
    }
    return json(status, publicReadiness(assessment));
  }

  /** Register a feature module: {routes: [{method, pattern, handler}], readinessChecks?()} */
  function use(module) {
    context.modules.push(module);
    routes.push(...module.routes);
  }

  async function handle(request) {
    const started = Date.now();
    const url = new URL(request.url);
    const candidates = routes.filter(r => r.pattern.test(url.pathname));
    let response;
    let routeLabel = 'unmatched';
    try {
      if (!candidates.length) {
        response = errorResponse('NOT_FOUND');
      } else {
        const route = candidates.find(r => r.method === request.method);
        if (!route) {
          response = errorResponse('METHOD_NOT_ALLOWED');
        } else {
          routeLabel = route.label ?? route.pattern.source.replace(/[\\^$]/g, '');
          response = await route.handler(request, url.pathname.match(route.pattern), context);
        }
      }
    } catch (error) {
      if (error instanceof HttpError) response = errorResponse(error.code, { retryAfter: error.retryAfter, fields: error.fields });
      else {
        logger.error('request_failed', { route: routeLabel, code: errorCode(error) });
        response = errorResponse('SERVICE_UNAVAILABLE');
      }
    }
    logger.info('request', { method: request.method, route: routeLabel, statusCode: response.status, durationMs: Date.now() - started });
    return response;
  }

  async function close() {
    if (pool && ownsPool) await pool.end();
    pool = null;
  }

  return { config, context, use, handle, close };
}

/** Production composition: the API with every feature module registered. */
export function createHeardServer(options = {}) {
  const app = createApp(options);
  const adapter = options.adapter ?? selectAdapter(app.config.secureIntake);
  app.context.adapter = adapter;
  // The workflow engine is required for readiness only when private intake is enabled.
  app.use({ routes: [], readinessChecks: () => [adapterReadinessCheck(adapter, { required: app.config.intake.enabled })] });
  app.use(identityModule(app.context));
  app.use(consentModule(app.context));
  app.use(draftsModule(app.context));
  return app;
}
