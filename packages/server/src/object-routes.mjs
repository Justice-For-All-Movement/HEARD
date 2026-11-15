/** HEARD-13 HTTP routes: list a case's objects and download cleared objects only. */
import { authorizeCase, authorizeObject, withSession } from '@heard/authorization';
import { isUuid } from '@heard/database';
import { mapped } from './errors.mjs';
import { HttpError, json } from './http.mjs';
import { requireIntake } from './request.mjs';

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
            return (await client.query('SELECT storage_ref, quarantine_state, detected_type, size_bytes FROM heard_private_objects WHERE id=$1', [objectId])).rows[0];
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
    ],
  };
}
