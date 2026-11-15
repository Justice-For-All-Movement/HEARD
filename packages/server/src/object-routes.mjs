/** HEARD-13 HTTP routes: list a case's objects and download cleared objects only. */
import { authorizeCase, authorizeObject, withSession } from '@heard/authorization';
import { actorKind, assertSource, caseManifest, recordEvent, verifyObjectBytes } from '@heard/evidence';
import { cancelJob, caseJobs } from '@heard/jobs';
import { isUuid } from '@heard/database';
import { mapped } from './errors.mjs';
import { HttpError, json, readJson } from './http.mjs';
import { requireIntake, requireSameOrigin } from './request.mjs';

const EXTENSIONS = { 'image/jpeg': 'jpg', 'image/png': 'png', 'application/pdf': 'pdf', 'video/mp4': 'mp4', 'video/quicktime': 'mov', 'audio/mpeg': 'mp3', 'audio/mp4': 'm4a' };

export function objectsModule(context) {
  const { config } = context;
  const id = value => { if (!isUuid(value)) throw new HttpError('NOT_FOUND'); return value; };
  const available = () => { requireIntake(config); if (!context.storage) throw new HttpError('FEATURE_DISABLED'); };
  return {
    routes: [
      {
        method: 'GET', pattern: /^\/api\/v1\/my\/cases\/([^/]+)\/objects$/, label: '/api/v1/my/cases/:id/objects',
        handler: mapped(async (request, match) => {
          available();
          const session = await context.requireSession(request);
          const caseId = id(match[1]);
          const objects = await withSession(context.getPool(), session, async client => {
            await authorizeCase(client, session, session.assurance === 'staff_mfa' ? 'review.read_case' : 'case.read', caseId);
            return (await client.query('SELECT id, declared_type, size_bytes, quarantine_state, quarantine_reason, created_at FROM heard_private_objects WHERE case_id=$1 ORDER BY created_at', [caseId])).rows;
          });
          // Status only: no storage keys, digests of other parties or scanner signatures.
          return json(200, { objects: objects.map(o => ({ objectId: o.id, type: o.declared_type, size: Number(o.size_bytes), state: o.quarantine_state, reason: o.quarantine_reason })) });
        }),
      },
      {
        method: 'GET', pattern: /^\/api\/v1\/objects\/([^/]+)$/, label: '/api/v1/objects/:id',
        handler: mapped(async (request, match) => {
          available();
          const session = await context.requireSession(request);
          const objectId = id(match[1]);
          const object = await withSession(context.getPool(), session, async client => {
            await authorizeObject(client, session, 'evidence.read', objectId);
            const row = (await client.query('SELECT o.case_id, o.storage_ref, o.quarantine_state, o.detected_type, o.size_bytes, c.subject_id FROM heard_private_objects o LEFT JOIN heard_cases c ON c.id = o.case_id WHERE o.id=$1', [objectId])).rows[0];
            // Every release of bytes is attributable in the chain of handling (HEARD-14).
            if (row?.quarantine_state === 'cleared') await recordEvent(client, { objectId, caseId: row.case_id, operation: 'downloaded', actorKind: actorKind(session, row.subject_id), actorId: session.subjectId });
            return row;
          });
          // Unscanned, failed or rejected bytes are never served, even to their owner.
          if (!object || object.quarantine_state !== 'cleared' || !EXTENSIONS[object.detected_type]) throw new HttpError('NOT_EDITABLE');
          const iterator = context.storage.getObject(object.storage_ref)[Symbol.asyncIterator]();
          const body = new ReadableStream({
            async pull(controller) {
              try {
                const { value, done } = await iterator.next();
                if (done) controller.close(); else controller.enqueue(value);
              } catch { controller.error(new Error('STORAGE_READ_FAILED')); }
            },
            async cancel() { await iterator.return?.(); },
          });
          return new Response(body, {
            status: 200,
            headers: {
              'content-type': object.detected_type,
              'content-length': String(object.size_bytes),
              'content-disposition': `attachment; filename="heard-${objectId}.${EXTENSIONS[object.detected_type]}"`,
              'cache-control': 'no-store',
              'x-content-type-options': 'nosniff',
              'content-security-policy': "default-src 'none'; sandbox",
              'cross-origin-resource-policy': 'same-origin',
              'referrer-policy': 'no-referrer',
            },
          });
        }),
      },
      {
        method: 'GET', pattern: /^\/api\/v1\/my\/cases\/([^/]+)\/jobs$/, label: '/api/v1/my/cases/:id/jobs',
        handler: mapped(async (request, match) => {
          requireIntake(config);
          const session = await context.requireSession(request);
          const caseId = id(match[1]);
          return json(200, { jobs: await withSession(context.getPool(), session, async client => {
            await authorizeCase(client, session, 'case.read', caseId);
            return caseJobs(client, caseId);
          }) });
        }),
      },
      {
        method: 'POST', pattern: /^\/api\/v1\/jobs\/([^/]+)\/cancel$/, label: '/api/v1/jobs/:id/cancel',
        handler: mapped(async (request, match) => {
          requireIntake(config);
          requireSameOrigin(request, config);
          const session = await context.requireSession(request);
          const jobId = id(match[1]);
          await withSession(context.getPool(), session, client => cancelJob(client, jobId));
          return json(200, { jobId, state: 'cancelled' });
        }),
      },
      {
        method: 'POST', pattern: /^\/api\/v1\/objects\/([^/]+)\/verify$/, label: '/api/v1/objects/:id/verify',
        handler: mapped(async (request, match) => {
          available();
          requireSameOrigin(request, config);
          const session = await context.requireSession(request);
          const objectId = id(match[1]);
          return json(200, await withSession(context.getPool(), session, client => verifyObjectBytes(client, session, context.storage, objectId)));
        }),
      },
      {
        method: 'POST', pattern: /^\/api\/v1\/objects\/([^/]+)\/source$/, label: '/api/v1/objects/:id/source',
        handler: mapped(async (request, match) => {
          available();
          requireSameOrigin(request, config);
          const session = await context.requireSession(request);
          const objectId = id(match[1]);
          const body = await readJson(request);
          if (Object.keys(body).some(k => !['source', 'captured'].includes(k))) throw new HttpError('INVALID_REQUEST');
          return json(201, await withSession(context.getPool(), session, client => assertSource(client, session, objectId, { source: body.source, captured: body.captured })));
        }),
      },
      {
        method: 'GET', pattern: /^\/api\/v1\/my\/cases\/([^/]+)\/evidence-manifest$/, label: '/api/v1/my/cases/:id/evidence-manifest',
        handler: mapped(async (request, match) => {
          available();
          const session = await context.requireSession(request);
          const caseId = id(match[1]);
          return json(200, await withSession(context.getPool(), session, client => caseManifest(client, session, caseId)));
        }),
      },
    ],
  };
}
