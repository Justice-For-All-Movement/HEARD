/** HEARD-09 HTTP routes: public policy texts, per-case consent state and decisions. */
import { withSession } from '@heard/authorization';
import { caseConsentState, publicPolicies, recordConsent } from '@heard/consent';
import { isUuid } from '@heard/database';
import { mapped } from './errors.mjs';
import { HttpError, json, readJson } from './http.mjs';
import { requireIntake, requireSameOrigin } from './request.mjs';

const CASE_CONSENTS = /^\/api\/v1\/my\/cases\/([^/]+)\/consents$/;

export function consentModule(context) {
  const { config } = context;
  const caseId = match => {
    if (!isUuid(match[1])) throw new HttpError('NOT_FOUND');
    return match[1];
  };
  return {
    routes: [
      {
        method: 'GET', pattern: /^\/api\/v1\/consent\/policies$/, label: '/api/v1/consent/policies',
        handler: () => { requireIntake(config); return json(200, { policies: publicPolicies() }); },
      },
      {
        method: 'GET', pattern: CASE_CONSENTS, label: '/api/v1/my/cases/:id/consents',
        handler: mapped(async (request, match) => {
          const session = await context.requireSession(request);
          const id = caseId(match);
          return json(200, await withSession(context.getPool(), session, c => caseConsentState(c, session, id)));
        }),
      },
      {
        method: 'POST', pattern: CASE_CONSENTS, label: '/api/v1/my/cases/:id/consents',
        handler: mapped(async (request, match) => {
          requireIntake(config);
          requireSameOrigin(request, config);
          const session = await context.requireSession(request);
          const id = caseId(match);
          const body = await readJson(request);
          const allowed = new Set(['purpose', 'decision', 'policyVersion', 'scope', 'expiresAt']);
          if (Object.keys(body).some(k => !allowed.has(k))) throw new HttpError('INVALID_REQUEST');
          let expiresAt = null;
          if (body.expiresAt !== undefined && body.expiresAt !== null) {
            if (typeof body.expiresAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(body.expiresAt)) throw new HttpError('INVALID_REQUEST', { fields: { expiresAt: 'CONSENT_EXPIRY_INVALID' } });
            expiresAt = new Date(body.expiresAt);
          }
          const state = await withSession(context.getPool(), session, c => recordConsent(c, session, id, { purpose: body.purpose, decision: body.decision, policyVersion: body.policyVersion, scope: body.scope ?? {}, expiresAt }));
          return json(201, state);
        }),
      },
    ],
  };
}
