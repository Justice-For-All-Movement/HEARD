/** Request guards shared by private API modules: feature flag, same-origin, session cookie, client key. */
import { HttpError, parseCookies } from './http.mjs';

export const SESSION_COOKIE = '__Host-heard_session';

/** Private routes do not exist while the intake feature flag is off. */
export function requireIntake(config) {
  if (!config.intake.enabled) throw new HttpError('FEATURE_DISABLED');
}

/**
 * CSRF defense for state-changing requests: require an Origin header equal to the
 * configured public origin (or, when unset in local/ci, the request's own origin),
 * reject cross-site fetch metadata, and require JSON bodies (no simple-form posts).
 */
export function requireSameOrigin(request, config) {
  const origin = request.headers.get('origin');
  const expected = config.publicOrigin ?? new URL(request.url).origin;
  if (!origin || origin !== expected) throw new HttpError('FORBIDDEN_ORIGIN');
  const site = request.headers.get('sec-fetch-site');
  if (site && !['same-origin', 'none'].includes(site)) throw new HttpError('FORBIDDEN_ORIGIN');
}

export function sessionToken(request) {
  return parseCookies(request.headers.get('cookie')).get(SESSION_COOKIE) ?? null;
}

export function sessionCookie(token, expiresAt) {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
export function clearedSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/**
 * Key for abuse throttling. Behind Render's proxy the right-most X-Forwarded-For
 * entry is the address the proxy observed; earlier entries are client-controlled.
 * The value is HMAC'd by the limiter and never stored.
 */
export function clientKey(request) {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    const parts = forwarded.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length) return parts.at(-1);
  }
  return request.headers.get('x-real-ip') ?? 'direct';
}
