/** HEARD-12 HTTP routes: start, upload parts, inspect, complete and abort private uploads. */
import { isUuid } from '@heard/database';
import { CHUNK_SIZE, createUploadService } from '@heard/uploads';
import { mapped } from './errors.mjs';
import { HttpError, json, readBytes, readJson } from './http.mjs';
import { requireIntake, requireSameOrigin } from './request.mjs';

const START = /^\/api\/v1\/drafts\/([^/]+)\/uploads$/;
const UPLOAD = /^\/api\/v1\/uploads\/([^/]+)$/;
const PART = /^\/api\/v1\/uploads\/([^/]+)\/parts\/(\d{1,5})$/;
const COMPLETE = /^\/api\/v1\/uploads\/([^/]+)\/complete$/;

export function uploadsModule(context) {
  const { config } = context;
  let service;
  const uploads = () => {
    // Uploads exist only when intake is enabled AND private storage is configured.
    if (!context.storage) throw new HttpError('FEATURE_DISABLED');
    service ??= createUploadService({ pool: context.getPool(), storage: context.storage, onObjectQuarantined: (client, input) => context.onObjectQuarantined?.(client, input) });
    return service;
  };
  const id = value => { if (!isUuid(value)) throw new HttpError('NOT_FOUND'); return value; };
  const guard = async (request, { mutate = true } = {}) => {
    requireIntake(config);
    uploads();
    if (mutate) requireSameOrigin(request, config);
    return context.requireSession(request);
  };
  const wrap = handler => mapped(async (...args) => {
    try { return await handler(...args); } catch (error) {
      if (error?.code === 'UPLOAD_QUOTA_REACHED') throw new HttpError('RATE_LIMITED', { retryAfter: 3600 });
      if (['UPLOAD_NOT_OPEN', 'UPLOAD_EXPIRED', 'UPLOAD_PARTS_MISSING'].includes(error?.code)) throw new HttpError('NOT_EDITABLE');
      if (error?.code === 'UPLOAD_INTEGRITY_FAILED') throw new HttpError('INVALID_REQUEST', { fields: { file: 'UPLOAD_INTEGRITY_FAILED' } });
      if (error?.code === 'UPLOAD_ASSEMBLY_FAILED' || error?.code === 'UPLOADS_UNAVAILABLE' || /^STORAGE_/.test(error?.code ?? '')) throw new HttpError('SERVICE_UNAVAILABLE');
      throw error;
    }
  });

  return {
    readinessChecks: () => context.storage ? [{ name: 'objectStorage', required: config.intake.enabled, probe: () => context.storage.health() }] : [],
    routes: [
      {
        method: 'POST', pattern: START, label: '/api/v1/drafts/:id/uploads',
        handler: wrap(async (request, match) => {
          const session = await guard(request);
          const body = await readJson(request);
          if (Object.keys(body).some(k => !['type', 'size', 'sha256'].includes(k))) throw new HttpError('INVALID_REQUEST');
          return json(201, await uploads().start(session, id(match[1]), body));
        }),
      },
      {
        method: 'PUT', pattern: PART, label: '/api/v1/uploads/:id/parts/:n',
        handler: wrap(async (request, match) => {
          const session = await guard(request);
          const bytes = await readBytes(request, { maxBytes: CHUNK_SIZE });
          return json(200, await uploads().putPart(session, id(match[1]), Number(match[2]), bytes));
        }),
      },
      {
        method: 'GET', pattern: UPLOAD, label: '/api/v1/uploads/:id',
        handler: wrap(async (request, match) => json(200, await uploads().status(await guard(request, { mutate: false }), id(match[1])))),
      },
      {
        method: 'POST', pattern: COMPLETE, label: '/api/v1/uploads/:id/complete',
        handler: wrap(async (request, match) => json(201, await uploads().complete(await guard(request), id(match[1])))),
      },
      {
        method: 'DELETE', pattern: UPLOAD, label: '/api/v1/uploads/:id',
        handler: wrap(async (request, match) => json(200, await uploads().abort(await guard(request), id(match[1])))),
      },
    ],
  };
}
