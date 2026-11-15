import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, ACTIONS } from '../packages/authorization/src/index.mjs';

const owner = { subjectId: 'owner', assurance: 'anonymous_recovery' };
const other = { subjectId: 'other', assurance: 'anonymous_recovery' };
const reviewer = { subjectId: 'rev', assurance: 'staff_mfa', staffRoles: ['reviewer'] };
const admin = { subjectId: 'adm', assurance: 'staff_mfa', staffRoles: ['administrator', 'reviewer', 'editor', 'safety'] };
const draft = { type: 'case', id: 'c1', ownerId: 'owner', status: 'draft' };
const submitted = { ...draft, status: 'submitted' };
const now = new Date('2026-11-15T12:00:00Z');
const later = new Date('2026-11-16T12:00:00Z');
const assigned = { now, assignments: [{ caseId: 'c1', role: 'reviewer', expiresAt: later, revokedAt: null }] };

test('owners act on their own cases only within state rules', () => {
  assert.equal(decide(owner, 'case.edit_draft', draft).allow, true);
  assert.equal(decide(owner, 'case.edit_draft', submitted).reason, 'state_forbids_action');
  assert.equal(decide(owner, 'case.submit', submitted).allow, false);
  assert.equal(decide(other, 'case.read', draft).allow, false);
  assert.equal(decide(owner, 'review.decide', submitted).reason, 'self_review_forbidden');
});

test('everything not explicitly allowed is denied', () => {
  for (const action of ACTIONS) assert.equal(decide(other, action, submitted, assigned).allow, false, action);
  assert.equal(decide(owner, 'case.delete_everything', draft).reason, 'unknown_action');
  assert.equal(decide(null, 'case.read', draft).reason, 'unauthenticated');
  assert.equal(decide(owner, 'case.read', null).reason, 'resource_unverified');
  assert.equal(decide({ subjectId: 'owner', assurance: 'x' }, 'case.read', { ...draft, ownerId: undefined }).allow, false);
});

test('staff need MFA, a role and a live assignment; administrator alone grants nothing', () => {
  assert.equal(decide(reviewer, 'review.read_case', submitted, assigned).allow, true);
  assert.equal(decide({ ...reviewer, assurance: 'anonymous_recovery' }, 'review.read_case', submitted, assigned).reason, 'staff_mfa_required');
  assert.equal(decide(reviewer, 'review.read_case', submitted, { now }).reason, 'no_assignment');
  assert.equal(decide(reviewer, 'review.read_case', submitted, { now: new Date('2026-11-17T00:00:00Z'), assignments: assigned.assignments }).reason, 'no_assignment', 'expired assignment');
  assert.equal(decide(reviewer, 'review.read_case', submitted, { now, assignments: [{ ...assigned.assignments[0], revokedAt: now }] }).reason, 'no_assignment');
  assert.equal(decide(reviewer, 'review.read_case', draft, assigned).reason, 'state_forbids_action', 'drafts are never visible to reviewers');
  assert.equal(decide(reviewer, 'publication.review', { ...submitted, status: 'review' }, assigned).allow, false, 'reviewer role cannot approve publication');
  assert.equal(decide(admin, 'review.read_case', submitted, { now }).allow, false);
  assert.equal(decide({ ...reviewer, staffRoles: [] }, 'review.read_case', submitted, assigned).allow, false, 'assignment without current role');
});

test('helper access is per object, per action, unexpired and unrevoked', () => {
  const object = { type: 'object', id: 'o1', caseId: 'c1', ownerId: 'owner', caseStatus: 'submitted' };
  const grant = { objectId: 'o1', recipientId: 'other', action: 'read', expiresAt: later, revokedAt: null };
  assert.equal(decide(other, 'evidence.read', object, { now, grants: [grant] }).allow, true);
  assert.equal(decide(other, 'evidence.read', { ...object, id: 'o2' }, { now, grants: [grant] }).allow, false);
  assert.equal(decide(other, 'evidence.read', object, { now, grants: [{ ...grant, action: 'download' }] }).allow, false);
  assert.equal(decide(other, 'evidence.read', object, { now, grants: [{ ...grant, revokedAt: now }] }).allow, false);
  assert.equal(decide(other, 'evidence.read', object, { now: later, grants: [grant] }).allow, false);
  assert.equal(decide({ subjectId: 'third', assurance: 'anonymous_recovery' }, 'evidence.read', object, { now, grants: [grant] }).allow, false);
  assert.equal(decide(other, 'case.read', submitted, { now, grants: [grant] }).allow, false, 'object grant never implies case access');
});

test('identity reveal requires two distinct independent safety approvals', () => {
  const safety = { subjectId: 's1', assurance: 'staff_mfa', staffRoles: ['safety'] };
  const approvals = [{ staffSubjectId: 's2', role: 'safety' }, { staffSubjectId: 's3', role: 'safety' }];
  assert.equal(decide(safety, 'identity.reveal', submitted, { revealApprovals: approvals }).allow, true);
  assert.equal(decide(safety, 'identity.reveal', submitted, { revealApprovals: [approvals[0], approvals[0]] }).allow, false);
  assert.equal(decide(safety, 'identity.reveal', submitted, { revealApprovals: [approvals[0], { staffSubjectId: 's1', role: 'safety' }] }).allow, false, 'self-approval');
  assert.equal(decide(admin, 'identity.reveal', submitted, { revealApprovals: [] }).allow, false, 'administrator alone cannot reveal');
  assert.equal(decide({ ...safety, assurance: 'anonymous_recovery' }, 'identity.reveal', submitted, { revealApprovals: approvals }).allow, false);
});
