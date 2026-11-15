/** HEARD-07 HTTP routes: anonymous start, recovery redemption, session and profile. */
import { createRateLimiter, endSession, getProfile, IdentityError, redeemRecovery, resolveSession, rotateRecoveryCode, setProfile, startAnonymous } from '@heard/identity';
import { HttpError, json, readJson } from './http.mjs';
import { clearedSessionCookie, clientKey, requireIntake, requireSameOrigin, sessionCookie, sessionToken } from './request.mjs';

const PRIVACY_NOTICE = 'HEARD stores a random identifier, a hashed recovery code and a hashed session token. Hosting, database and network providers can still observe connection metadata such as IP addresses and timing; a pseudonym or anonymous session does not hide those.';

export function identityModule(context) {
  const { config } = context;
  const secret = config.secrets.sessionSecret;
  const startLimiter = createRateLimiter({ limit: 10, windowMs: 60 * 60 * 1000, secret });
  const redeemLimiter = createRateLimiter({ limit: 10, windowMs: 15 * 60 * 1000, secret });

  /** Resolve the caller's session or fail with a uniform 401. */
  async function requireSession(request) {
    requireIntake(config);
    const session = await resolveSession(context.getPool(), sessionToken(request), { secret });
    if (!session) throw new HttpError('UNAUTHENTICATED');
    return session;
  }
  context.requireSession = requireSession;

  function throttle(limiter, request) {
    const verdict = limiter.check(clientKey(request));
    if (!verdict.allowed) throw new HttpError('RATE_LIMITED', { retryAfter: verdict.retryAfterMs / 1000 });
  }

  const mutating = request => { requireIntake(config); requireSameOrigin(request, config); };

  return {
    routes: [
      {
        method: 'POST', pattern: /^\/api\/v1\/anonymous\/start$/, label: '/api/v1/anonymous/start',
        async handler(request) {
          mutating(request);
          throttle(startLimiter, request);
          await readJson(request);
          const result = await startAnonymous(context.getPool(), { secret });
          return json(201, { recoveryCode: result.recoveryCode, expiresAt: result.expiresAt.toISOString(), notice: PRIVACY_NOTICE }, { 'set-cookie': sessionCookie(result.token, result.expiresAt) });
        },
      },
      {
        method: 'POST', pattern: /^\/api\/v1\/anonymous\/redeem$/, label: '/api/v1/anonymous/redeem',
        async handler(request) {
          mutating(request);
          throttle(redeemLimiter, request);
          const body = await readJson(request);
          try {
            const result = await redeemRecovery(context.getPool(), body.recoveryCode, { secret, presentedToken: sessionToken(request) });
            return json(200, { recoveryCode: result.recoveryCode, expiresAt: result.expiresAt.toISOString(), notice: 'Your previous recovery code no longer works. Save this new one.' }, { 'set-cookie': sessionCookie(result.token, result.expiresAt) });
          } catch (error) {
            if (error instanceof IdentityError) throw new HttpError('INVALID_RECOVERY_CODE');
            throw error;
          }
        },
      },
      {
        method: 'GET', pattern: /^\/api\/v1\/session$/, label: '/api/v1/session',
        async handler(request) {
          const session = await requireSession(request);
          const profile = await getProfile(context.getPool(), session);
          return json(200, { authenticated: true, assurance: session.assurance, expiresAt: session.expiresAt.toISOString(), profile });
        },
      },
      {
        method: 'DELETE', pattern: /^\/api\/v1\/session$/, label: '/api/v1/session',
        async handler(request) {
          mutating(request);
          const session = await requireSession(request);
          await endSession(context.getPool(), session);
          return new Response(null, { status: 204, headers: { 'set-cookie': clearedSessionCookie(), 'cache-control': 'no-store' } });
        },
      },
      {
        method: 'POST', pattern: /^\/api\/v1\/recovery\/rotate$/, label: '/api/v1/recovery/rotate',
        async handler(request) {
          mutating(request);
          const session = await requireSession(request);
          await readJson(request);
          const { recoveryCode } = await rotateRecoveryCode(context.getPool(), session, { secret });
          return json(200, { recoveryCode, notice: 'Your previous recovery code no longer works.' });
        },
      },
      {
        method: 'PUT', pattern: /^\/api\/v1\/profile$/, label: '/api/v1/profile',
        async handler(request) {
          mutating(request);
          const session = await requireSession(request);
          const body = await readJson(request);
          const allowed = new Set(['alias', 'language']);
          if (Object.keys(body).some(k => !allowed.has(k))) throw new HttpError('INVALID_REQUEST');
          try {
            return json(200, { profile: await setProfile(context.getPool(), session, { alias: body.alias ?? null, language: body.language ?? 'en' }) });
          } catch (error) {
            if (error instanceof IdentityError) throw new HttpError('INVALID_REQUEST', { fields: { alias: error.code } });
            throw error;
          }
        },
      },
    ],
  };
}
