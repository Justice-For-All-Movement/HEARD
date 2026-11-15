/** HEARD-10/11 HTTP routes: intake schema, drafts, submission receipts and own-case status. */
import { isUuid } from '@heard/database';
import { createDraftService } from '@heard/drafts';
import { IntakeValidationError, publicSchema } from '@heard/intake';
import { mapped } from './errors.mjs';
import { HttpError, json, readJson } from './http.mjs';
import { requireIntake, requireSameOrigin } from './request.mjs';

const DRAFT = /^\/api\/v1\/drafts\/([^/]+)$/;
const SUBMIT = /^\/api\/v1\/drafts\/([^/]+)\/submit$/;
const MY_CASE = /^\/api\/v1\/my\/cases\/([^/]+)$/;

export function draftsModule(context) {
  const { config } = context;
  let service;
  const drafts = () => {
    service ??= createDraftService({
      pool: context.getPool(),
      adapter: context.adapter,
      crypto: { key: config.secrets.dataKey, keyId: config.secrets.dataKeyId },
      secret: config.secrets.sessionSecret,
    });
    return service;
  };
  const id = match => { if (!isUuid(match[1])) throw new HttpError('NOT_FOUND'); return match[1]; };
  const only = (body, keys) => { if (Object.keys(body).some(k => !keys.includes(k))) throw new HttpError('INVALID_REQUEST'); };
  const validation = handler => mapped(async (...args) => {
    try { return await handler(...args); } catch (error) {
      if (error instanceof IntakeValidationError) throw new HttpError('INVALID_REQUEST', { fields: error.errors });
      if (error?.code === 'DRAFT_LIMIT_REACHED') throw new HttpError('RATE_LIMITED', { retryAfter: 3600 });
      throw error;
    }
  });
  const view = d => ({ caseId: d.caseId, kind: d.kind, status: d.status, revision: d.revision, schemaVersion: d.schemaVersion, answers: d.answers, updatedAt: d.updatedAt, expiresAt: d.expiresAt, receipt: d.receipt });
  const mutate = async request => { requireIntake(config); requireSameOrigin(request, config); return context.requireSession(request); };

  return {
    routes: [
      { method: 'GET', pattern: /^\/api\/v1\/intake\/schema$/, label: '/api/v1/intake/schema', handler: () => { requireIntake(config); return json(200, publicSchema()); } },
      {
        method: 'POST', pattern: /^\/api\/v1\/drafts$/, label: '/api/v1/drafts',
        handler: validation(async request => {
          const session = await mutate(request);
          const body = await readJson(request);
          only(body, ['kind']);
          return json(201, await drafts().create(session, { kind: body.kind }));
        }),
      },
      {
        method: 'GET', pattern: DRAFT, label: '/api/v1/drafts/:id',
        handler: validation(async (request, match) => {
          const session = await context.requireSession(request);
          return json(200, view(await drafts().get(session, id(match))));
        }),
      },
      {
        method: 'PUT', pattern: DRAFT, label: '/api/v1/drafts/:id',
        handler: validation(async (request, match) => {
          const session = await mutate(request);
          const body = await readJson(request, { maxBytes: 128 * 1024 });
          only(body, ['revision', 'answers']);
          return json(200, await drafts().save(session, id(match), { revision: body.revision, answers: body.answers }));
        }),
      },
      {
        method: 'DELETE', pattern: DRAFT, label: '/api/v1/drafts/:id',
        handler: validation(async (request, match) => {
          const session = await mutate(request);
          return json(200, await drafts().withdraw(session, id(match)));
        }),
      },
      {
        method: 'POST', pattern: SUBMIT, label: '/api/v1/drafts/:id/submit',
        handler: validation(async (request, match) => {
          const session = await mutate(request);
          const body = await readJson(request);
          only(body, ['revision']);
          const receipt = await drafts().submit(session, id(match), { revision: body.revision, idempotencyKey: request.headers.get('idempotency-key') });
          return json(receipt.replayed ? 200 : 201, { reference: receipt.reference, status: receipt.status, submittedAt: receipt.submittedAt, nextSteps: receipt.nextSteps });
        }),
      },
      {
        method: 'GET', pattern: /^\/api\/v1\/my\/cases$/, label: '/api/v1/my/cases',
        handler: validation(async request => json(200, { cases: await drafts().listMine(await context.requireSession(request)) })),
      },
      {
        method: 'GET', pattern: MY_CASE, label: '/api/v1/my/cases/:id',
        handler: validation(async (request, match) => {
          const session = await context.requireSession(request);
          const d = await drafts().get(session, id(match));
          return json(200, { caseId: d.caseId, kind: d.kind, status: d.status, updatedAt: d.updatedAt, receipt: d.receipt });
        }),
      },
    ],
  };
}
