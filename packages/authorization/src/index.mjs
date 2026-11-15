/**
 * HEARD-08 deny-by-default authorization.
 *
 * Two layers, both required:
 *  1. `decide()` — pure policy-as-code over a server-resolved principal (from a
 *     verified session, never request fields) and a resource loaded inside the
 *     principal's scope. Every rule is explicit; anything unlisted is denied.
 *  2. PostgreSQL forced RLS (migrations 0005/0006) — rows outside the principal's
 *     reach are invisible even if application code has a bug.
 * Decisions on sensitive actions are appended to the audit log.
 */
import { withScope } from '@heard/database';
import { activeStaffRoles, audit } from '@heard/identity';

export const ACTIONS = Object.freeze([
  'case.read',
  'case.edit_draft',
  'case.submit',
  'case.withdraw',
  'consent.record',
  'evidence.upload',
  'evidence.read',
  'grant.create',
  'grant.revoke',
  'review.read_case',
  'review.decide',
  'publication.review',
  'identity.reveal',
]);

/** Actions that leave an audit record whether allowed or denied. */
export const AUDITED_ACTIONS = Object.freeze(new Set(['evidence.read', 'grant.create', 'grant.revoke', 'review.read_case', 'review.decide', 'publication.review', 'identity.reveal']));

const OWNER_ACTIONS = {
  'case.read': () => true,
  'case.edit_draft': r => r.status === 'draft',
  'case.submit': r => r.status === 'draft',
  'case.withdraw': r => ['draft', 'submitted', 'review'].includes(r.status),
  'consent.record': r => r.status !== 'withdrawn' && r.status !== 'closed',
  'evidence.upload': r => r.status === 'draft',
  'evidence.read': () => true,
  'grant.create': r => r.status !== 'withdrawn',
  'grant.revoke': () => true,
};

const STAFF_RULES = {
  'review.read_case': { roles: ['reviewer', 'editor', 'safety'], states: ['submitted', 'review', 'closed'] },
  'review.decide': { roles: ['reviewer'], states: ['submitted', 'review'] },
  'publication.review': { roles: ['editor'], states: ['review'] },
};

const deny = reason => Object.freeze({ allow: false, reason });
const allow = reason => Object.freeze({ allow: true, reason });

/**
 * @param {{subjectId:string, assurance:string, staffRoles?:string[]}} principal server-resolved
 * @param {string} action
 * @param {{type:'case', id:string, ownerId:string, status:string}|{type:'object', id:string, caseId:string, ownerId:string, caseStatus:string}} resource loaded in scope
 * @param {{now?:Date, assignments?:{caseId:string, role:string, expiresAt:Date, revokedAt:Date|null}[], grants?:{objectId:string, recipientId:string, action:string, expiresAt:Date, revokedAt:Date|null}[], revealApprovals?:{staffSubjectId:string, role:string}[]}} facts
 */
export function decide(principal, action, resource, facts = {}) {
  if (!ACTIONS.includes(action)) return deny('unknown_action');
  if (!principal || typeof principal.subjectId !== 'string' || !principal.subjectId) return deny('unauthenticated');
  if (!resource || typeof resource !== 'object' || typeof resource.id !== 'string' || typeof resource.ownerId !== 'string') return deny('resource_unverified');
  const now = facts.now ?? new Date();
  const isOwner = principal.subjectId === resource.ownerId;
  const caseState = resource.type === 'object' ? resource.caseStatus : resource.status;
  const caseId = resource.type === 'object' ? resource.caseId : resource.id;

  // Dual-control identity reveal: two distinct MFA-verified safety staff, neither the requester or owner.
  if (action === 'identity.reveal') {
    if (principal.assurance !== 'staff_mfa' || !(principal.staffRoles ?? []).includes('safety') || isOwner) return deny('reveal_requires_safety_staff');
    const approvers = new Set((facts.revealApprovals ?? []).filter(a => a.role === 'safety' && a.staffSubjectId !== principal.subjectId && a.staffSubjectId !== resource.ownerId).map(a => a.staffSubjectId));
    return approvers.size >= 2 ? allow('dual_control') : deny('reveal_requires_two_approvals');
  }

  if (isOwner && Object.hasOwn(OWNER_ACTIONS, action)) {
    return OWNER_ACTIONS[action]({ status: caseState }) ? allow('owner') : deny('state_forbids_action');
  }

  if (action === 'evidence.read' && resource.type === 'object' && !isOwner) {
    const grant = (facts.grants ?? []).find(g => g.objectId === resource.id && g.recipientId === principal.subjectId && g.action === 'read' && !g.revokedAt && g.expiresAt > now);
    if (grant) return allow('explicit_grant');
  }

  if (Object.hasOwn(STAFF_RULES, action) || action === 'evidence.read') {
    if (isOwner) return deny('self_review_forbidden');
    if (principal.assurance !== 'staff_mfa') return deny('staff_mfa_required');
    const rule = STAFF_RULES[action] ?? STAFF_RULES['review.read_case'];
    const roles = principal.staffRoles ?? [];
    const assignment = (facts.assignments ?? []).find(a => a.caseId === caseId && rule.roles.includes(a.role) && roles.includes(a.role) && !a.revokedAt && a.expiresAt > now);
    // Administrator (or any) role without an assignment to this case grants nothing.
    if (!assignment) return deny('no_assignment');
    return rule.states.includes(caseState) ? allow('assigned_staff') : deny('state_forbids_action');
  }
  return deny('no_rule');
}

export class AuthorizationError extends Error {
  constructor(reason, auditRecord = null) {
    // A state conflict only arises for principals who can already see the resource,
    // so it may be reported as such; every other denial is indistinguishable from absence.
    const code = reason === 'state_forbids_action' ? 'STATE_FORBIDS_ACTION' : 'NOT_FOUND';
    super(code); this.code = code; this.reason = reason; this.auditRecord = auditRecord;
  }
}

/**
 * Run fn in a transaction scoped to a verified session (subject + assurance for RLS).
 * A denial rolls the work back; its audit record is then committed separately so
 * denied attempts are never lost with the rolled-back transaction.
 */
export async function withSession(pool, session, fn) {
  const scope = { subjectId: session.subjectId, settings: { assurance: session.assurance } };
  try {
    return await withScope(pool, scope, fn);
  } catch (error) {
    if (error instanceof AuthorizationError && error.auditRecord) {
      const { action, metadata } = error.auditRecord;
      error.auditRecord = null;
      await withScope(pool, scope, c => audit(c, session.subjectId, action, 'deny', { metadata }));
    }
    throw error;
  }
}

/** Load the principal's server-side facts (staff roles) inside its own scope. */
export async function loadPrincipal(client, session, now = new Date()) {
  const staffRoles = session.assurance === 'staff_mfa' ? await activeStaffRoles(client, session.subjectId, now) : [];
  return { subjectId: session.subjectId, assurance: session.assurance, staffRoles };
}

/**
 * Authorize an action on a case inside an existing scoped transaction. Unknown and
 * forbidden cases both raise AuthorizationError('NOT_FOUND') so callers cannot
 * distinguish existence from denial. Returns the loaded case on success.
 */
export async function authorizeCase(client, session, action, caseId, { now = new Date() } = {}) {
  const principal = await loadPrincipal(client, session, now);
  const row = (await client.query('SELECT id, subject_id, status, kind FROM heard_cases WHERE id=$1', [caseId])).rows[0];
  const resource = row ? { type: 'case', id: row.id, ownerId: row.subject_id, status: row.status } : null;
  const assignments = row && principal.staffRoles.length
    ? (await client.query('SELECT case_id, role, expires_at, revoked_at FROM heard_case_assignments WHERE case_id=$1 AND staff_subject_id=$2', [caseId, session.subjectId])).rows.map(a => ({ caseId: a.case_id, role: a.role, expiresAt: a.expires_at, revokedAt: a.revoked_at }))
    : [];
  const decision = resource ? decide(principal, action, resource, { now, assignments }) : deny('not_visible');
  await recordDecision(client, session, action, decision, row ? caseId : null, caseId);
  return { id: row.id, ownerId: row.subject_id, status: row.status, kind: row.kind };
}

/** Authorize access to one private object (owner, assigned staff or explicit active grant). */
export async function authorizeObject(client, session, action, objectId, { now = new Date() } = {}) {
  const principal = await loadPrincipal(client, session, now);
  const row = (await client.query('SELECT o.id, o.case_id, o.quarantine_state, c.subject_id, c.status FROM heard_private_objects o LEFT JOIN heard_cases c ON c.id = o.case_id WHERE o.id=$1', [objectId])).rows[0];
  let decision = deny('not_visible');
  if (row) {
    // A grant recipient cannot see the case row; ownership comes from the grant record instead.
    const grants = (await client.query('SELECT object_id, recipient_id, grantor_id, action, expires_at, revoked_at FROM heard_resource_grants WHERE object_id=$1 AND (recipient_id=$2 OR grantor_id=$2)', [objectId, session.subjectId])).rows;
    const ownerId = row.subject_id ?? grants[0]?.grantor_id ?? null;
    const assignments = principal.staffRoles.length
      ? (await client.query('SELECT case_id, role, expires_at, revoked_at FROM heard_case_assignments WHERE case_id=$1 AND staff_subject_id=$2', [row.case_id, session.subjectId])).rows.map(a => ({ caseId: a.case_id, role: a.role, expiresAt: a.expires_at, revokedAt: a.revoked_at }))
      : [];
    if (ownerId) decision = decide(principal, action, { type: 'object', id: row.id, caseId: row.case_id, ownerId, caseStatus: row.status ?? 'submitted' }, {
      now, assignments,
      grants: grants.map(g => ({ objectId: g.object_id, recipientId: g.recipient_id, action: g.action, expiresAt: g.expires_at, revokedAt: g.revoked_at })),
    });
  }
  await recordDecision(client, session, action, decision, null, objectId);
  return { id: row.id, caseId: row.case_id, quarantineState: row.quarantine_state };
}

/** Allowed sensitive actions are audited in the same transaction; denials always throw with their audit record. */
async function recordDecision(client, session, action, decision, visibleCaseId, targetId) {
  // The target id is recorded in metadata, not as a foreign key, so a denied probe
  // cannot learn whether the target exists from a constraint error.
  const metadata = { reason: decision.reason, target: typeof targetId === 'string' && /^[0-9a-f-]{36}$/.test(targetId) ? targetId : 'invalid' };
  if (!decision.allow) throw new AuthorizationError(decision.reason, { action: `authz.${action}`, metadata });
  if (AUDITED_ACTIONS.has(action)) await audit(client, session.subjectId, `authz.${action}`, 'allow', { caseId: visibleCaseId, metadata });
}

/** Create a time-limited, single-object, single-action grant from the case owner to a recipient. */
export async function createGrant(client, session, { caseId, objectId, recipientId, action = 'read', purpose, expiresAt, now = new Date() }) {
  await authorizeCase(client, session, 'grant.create', caseId, { now });
  if (!(expiresAt instanceof Date) || expiresAt <= now || expiresAt.getTime() - now.getTime() > 90 * 86_400_000) throw new AuthorizationError('grant_expiry_invalid');
  const row = (await client.query(
    'INSERT INTO heard_resource_grants(case_id, object_id, grantor_id, recipient_id, action, purpose, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
    [caseId, objectId, session.subjectId, recipientId, action, purpose, expiresAt])).rows[0];
  await audit(client, session.subjectId, 'grant.created', 'allow', { caseId, metadata: { reason: action } });
  return row.id;
}

export async function revokeGrant(client, session, grantId, { now = new Date() } = {}) {
  const result = await client.query('UPDATE heard_resource_grants SET revoked_at=$3 WHERE id=$1 AND grantor_id=$2 AND revoked_at IS NULL RETURNING case_id', [grantId, session.subjectId, now]);
  if (result.rowCount !== 1) throw new AuthorizationError('not_visible', { action: 'authz.grant.revoke', metadata: { reason: 'not_visible', target: /^[0-9a-f-]{36}$/.test(String(grantId)) ? grantId : 'invalid' } });
  await audit(client, session.subjectId, 'grant.revoked', 'allow', { caseId: result.rows[0].case_id });
}

/** Operator-only: assign MFA staff to a case for a stated purpose and limited time. */
export async function assignStaff(pool, { caseId, staffSubjectId, role, purpose, expiresAt, assignedBy = null }) {
  return withScope(pool, { role: 'heard_operator', settings: { operator_purpose: 'case_assignment' } }, async client => {
    const staff = (await client.query('SELECT 1 FROM heard_staff_memberships WHERE subject_id=$1 AND role=$2 AND revoked_at IS NULL AND expires_at > now()', [staffSubjectId, role])).rows;
    if (!staff.length) throw new AuthorizationError('not_staff_in_role');
    return (await client.query('INSERT INTO heard_case_assignments(case_id, staff_subject_id, role, purpose, expires_at, assigned_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id', [caseId, staffSubjectId, role, purpose, expiresAt, assignedBy])).rows[0].id;
  });
}
