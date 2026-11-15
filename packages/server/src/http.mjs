/** Shared HTTP helpers: uniform, non-enumerating JSON responses with private cache headers. */

export const SECURITY_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'cross-origin-resource-policy': 'same-origin',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
});

export function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...headers },
  });
}

/** Stable error vocabulary. Messages are generic and never echo input. */
const ERRORS = {
  NOT_FOUND: [404, 'Not found.'],
  METHOD_NOT_ALLOWED: [405, 'Method not allowed.'],
  UNAUTHENTICATED: [401, 'Sign-in or a valid recovery session is required.'],
  FORBIDDEN_ORIGIN: [403, 'Request origin is not allowed.'],
  INVALID_REQUEST: [400, 'The request could not be processed.'],
  UNSUPPORTED_MEDIA_TYPE: [415, 'Send application/json.'],
  PAYLOAD_TOO_LARGE: [413, 'The request is too large.'],
  CONFLICT: [409, 'This draft changed elsewhere. Reload before saving again.'],
  CONSENT_REQUIRED: [409, 'A required privacy choice has not been made.'],
  NOT_EDITABLE: [409, 'This record can no longer be changed.'],
  RATE_LIMITED: [429, 'Too many attempts. Please wait and try again.'],
  SERVICE_UNAVAILABLE: [503, 'Service is temporarily unavailable.'],
  FEATURE_DISABLED: [404, 'Not found.'],
  INVALID_RECOVERY_CODE: [401, 'That recovery code was not accepted.'],
};

export class HttpError extends Error {
  constructor(code, { retryAfter, fields } = {}) {
    super(code);
    this.code = code;
    this.retryAfter = retryAfter;
    this.fields = fields;
  }
}

export function errorResponse(code, { retryAfter, fields } = {}) {
  const [status, message] = ERRORS[code] ?? ERRORS.SERVICE_UNAVAILABLE;
  const effective = ERRORS[code] ? code : 'SERVICE_UNAVAILABLE';
  // A disabled feature is indistinguishable from an unknown route.
  const publicCode = effective === 'FEATURE_DISABLED' ? 'NOT_FOUND' : effective;
  const headers = retryAfter ? { 'retry-after': String(Math.ceil(retryAfter)) } : {};
  return json(status, { error: { code: publicCode, message, ...(fields ? { fields } : {}) } }, headers);
}

const MAX_BODY = 64 * 1024;
/** Parse a bounded JSON object body. */
export async function readJson(request, { maxBytes = MAX_BODY } = {}) {
  const type = request.headers.get('content-type') ?? '';
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(type.trim())) throw new HttpError('UNSUPPORTED_MEDIA_TYPE');
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > maxBytes) throw new HttpError('PAYLOAD_TOO_LARGE');
  const text = await request.text();
  if (Buffer.byteLength(text) > maxBytes) throw new HttpError('PAYLOAD_TOO_LARGE');
  let value;
  try { value = JSON.parse(text); } catch { throw new HttpError('INVALID_REQUEST'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new HttpError('INVALID_REQUEST');
  return value;
}

export function parseCookies(header) {
  const out = new Map();
  for (const part of (header ?? '').split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    if (!out.has(name)) out.set(name, part.slice(index + 1).trim());
  }
  return out;
}
