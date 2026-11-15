/** Map domain errors to the uniform HTTP vocabulary. Unknown errors propagate (→ 503, logged by code). */
import { HttpError } from './http.mjs';

export function mapDomainError(error) {
  if (error instanceof HttpError) return error;
  const code = error?.code;
  if (code === 'STATE_FORBIDS_ACTION') return new HttpError('NOT_EDITABLE');
  if (error?.name === 'AuthorizationError' || code === 'NOT_FOUND' || code === 'ADAPTER_NOT_FOUND') return new HttpError('NOT_FOUND');
  if (code === 'DRAFT_KEY_UNAVAILABLE' || code === 'DRAFT_CIPHERTEXT_INVALID') return new HttpError('SERVICE_UNAVAILABLE');
  if (code === 'CONSENT_POLICY_STALE' || code === 'DRAFT_REVISION_CONFLICT') return new HttpError('CONFLICT', error.field ? { fields: { [error.field]: code } } : {});
  if (code === 'CONSENT_REQUIRED') return new HttpError('CONSENT_REQUIRED', error.field ? { fields: { purpose: error.field } } : {});
  if (code === 'ADAPTER_STATE_CONFLICT' || code === 'ADAPTER_INVALID_TRANSITION' || code === 'DRAFT_NOT_EDITABLE') return new HttpError('NOT_EDITABLE');
  if (typeof code === 'string' && /^(CONSENT|INTAKE|DRAFT|ADAPTER_INVALID|UPLOAD)_/.test(code)) return new HttpError('INVALID_REQUEST', error.field ? { fields: { [error.field]: code } } : {});
  return error;
}

/** Wrap a handler so domain errors become HttpErrors. */
export const mapped = handler => async (...args) => {
  try { return await handler(...args); } catch (error) { throw mapDomainError(error); }
};
