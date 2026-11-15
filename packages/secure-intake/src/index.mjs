/**
 * HEARD-05 Secure Intake & Case Workflow Engine adapter boundary.
 *
 * HEARD talks to case workflow only through this interface. Two implementations:
 *  - `local`: HEARD-owned PostgreSQL workflow (cases + append-only case events)
 *    operating inside the caller's already-authorized, RLS-scoped transaction.
 *  - `remote`: the upstream engine over HTTPS. No upstream API version has been
 *    verified against a real deployment, so VERIFIED_UPSTREAM_VERSIONS is empty and
 *    the remote adapter reports itself unavailable instead of claiming readiness.
 *    It never silently falls back to the local adapter.
 */

export const ADAPTER_CONTRACT_VERSION = '1.0.0';

/** Capabilities a HEARD feature may require. Unsupported ones fail with ADAPTER_CAPABILITY_UNSUPPORTED. */
export const CAPABILITIES = Object.freeze([
  'case.create_draft',
  'case.submit',
  'case.withdraw',
  'case.read_status',
  'case.record_event',
  'case.transition_review',
  'case.assign_reviewer',
  'case.helper_grant',
]);

/** Upstream engine API versions verified by real contract tests. None yet: recorded blocker. */
export const VERIFIED_UPSTREAM_VERSIONS = Object.freeze([]);

export const CASE_KINDS = Object.freeze(['question', 'experience', 'support']);
export const CASE_STATES = Object.freeze(['draft', 'submitted', 'review', 'closed', 'withdrawn']);
/** Allowed case-state transitions. Anything else is rejected. */
export const CASE_TRANSITIONS = Object.freeze({
  draft: Object.freeze(['submitted', 'withdrawn']),
  submitted: Object.freeze(['review', 'withdrawn']),
  review: Object.freeze(['closed', 'withdrawn']),
  closed: Object.freeze([]),
  withdrawn: Object.freeze([]),
});
export function canTransition(from, to) {
  return Object.hasOwn(CASE_TRANSITIONS, from) && CASE_TRANSITIONS[from].includes(to);
}

/** Event types the adapter may record; payload metadata must be minimal and non-narrative. */
export const EVENT_TYPES = Object.freeze(['case_created', 'case_submitted', 'case_withdrawn', 'review_started', 'case_closed', 'info_requested']);
const SAFE_METADATA_KEYS = new Set(['schemaVersion', 'policyVersion', 'reason', 'channel']);

export class AdapterError extends Error {
  constructor(code) { super(code); this.code = code; this.name = 'AdapterError'; }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function assertUuid(value) { if (typeof value !== 'string' || !UUID.test(value)) throw new AdapterError('ADAPTER_INVALID_REQUEST'); }

/** Event metadata is restricted to short allowlisted scalars: never narrative, names or contact data. */
export function sanitizeEventMetadata(metadata = {}) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new AdapterError('ADAPTER_INVALID_REQUEST');
  const out = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (!SAFE_METADATA_KEYS.has(key)) throw new AdapterError('ADAPTER_UNSAFE_METADATA');
    if (!(typeof value === 'number' || (typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(value)))) throw new AdapterError('ADAPTER_UNSAFE_METADATA');
    out[key] = value;
  }
  return out;
}

export function requireCapability(adapter, capability) {
  if (!CAPABILITIES.includes(capability)) throw new AdapterError('ADAPTER_UNKNOWN_CAPABILITY');
  if (!adapter.capabilities.has(capability)) throw new AdapterError('ADAPTER_CAPABILITY_UNSUPPORTED');
}

/**
 * HEARD-owned workflow on PostgreSQL. Every method receives the caller's
 * transaction client, which must already be scoped (withScope) to the
 * authenticated subject; RLS remains the final arbiter of row access.
 */
export function createLocalAdapter() {
  const capabilities = new Set(['case.create_draft', 'case.submit', 'case.withdraw', 'case.read_status', 'case.record_event', 'case.transition_review']);

  async function recordEvent(client, { caseId, actorId = null, type, metadata = {} }) {
    assertUuid(caseId);
    if (actorId !== null) assertUuid(actorId);
    if (!EVENT_TYPES.includes(type)) throw new AdapterError('ADAPTER_INVALID_REQUEST');
    const safe = sanitizeEventMetadata(metadata);
    await client.query('INSERT INTO heard_case_events(case_id, actor_id, event_type, event_metadata) VALUES($1,$2,$3,$4)', [caseId, actorId, type, safe]);
  }

  async function transition(client, { caseId, actorId, from, to, event, metadata }) {
    assertUuid(caseId);
    if (!canTransition(from, to)) throw new AdapterError('ADAPTER_INVALID_TRANSITION');
    // Compare-and-set: a concurrent or replayed transition updates zero rows.
    const result = await client.query('UPDATE heard_cases SET status=$3, updated_at=now() WHERE id=$1 AND status=$2 RETURNING id', [caseId, from, to]);
    if (result.rowCount !== 1) throw new AdapterError('ADAPTER_STATE_CONFLICT');
    await recordEvent(client, { caseId, actorId, type: event, metadata });
  }

  return Object.freeze({
    id: 'local',
    contractVersion: ADAPTER_CONTRACT_VERSION,
    upstreamVersion: null,
    capabilities,
    async health() { return { status: 'ok', detail: { mode: 'local' } }; },
    async createDraft(client, { caseId, subjectId, kind }) {
      assertUuid(caseId); assertUuid(subjectId);
      if (!CASE_KINDS.includes(kind)) throw new AdapterError('ADAPTER_INVALID_REQUEST');
      await client.query("INSERT INTO heard_cases(id, subject_id, kind, status, visibility) VALUES($1,$2,$3,'draft','private')", [caseId, subjectId, kind]);
      await recordEvent(client, { caseId, actorId: subjectId, type: 'case_created', metadata: { channel: 'web' } });
      return { caseId, status: 'draft' };
    },
    async submit(client, { caseId, actorId, policyVersion }) {
      await transition(client, { caseId, actorId, from: 'draft', to: 'submitted', event: 'case_submitted', metadata: { policyVersion } });
      return { caseId, status: 'submitted' };
    },
    async withdraw(client, { caseId, actorId }) {
      const current = await this.readStatus(client, { caseId });
      await transition(client, { caseId, actorId, from: current.status, to: 'withdrawn', event: 'case_withdrawn', metadata: {} });
      return { caseId, status: 'withdrawn' };
    },
    async startReview(client, { caseId, actorId }) {
      await transition(client, { caseId, actorId, from: 'submitted', to: 'review', event: 'review_started', metadata: {} });
      return { caseId, status: 'review' };
    },
    async readStatus(client, { caseId }) {
      assertUuid(caseId);
      const row = (await client.query('SELECT status, kind, updated_at FROM heard_cases WHERE id=$1', [caseId])).rows[0];
      // Missing and unauthorized are indistinguishable to callers.
      if (!row) throw new AdapterError('ADAPTER_NOT_FOUND');
      return { caseId, status: row.status, kind: row.kind, updatedAt: row.updated_at };
    },
    recordEvent,
  });
}

/**
 * Remote engine adapter. Refuses to operate unless the configured API version is in
 * VERIFIED_UPSTREAM_VERSIONS; with none verified, it is a fail-closed placeholder that
 * makes no network request and reports a precise readiness blocker.
 */
export function createRemoteAdapter(config, { verifiedVersions = VERIFIED_UPSTREAM_VERSIONS } = {}) {
  const verified = typeof config?.apiVersion === 'string' && verifiedVersions.includes(config.apiVersion);
  const unavailable = async () => { throw new AdapterError(verified ? 'ADAPTER_NOT_IMPLEMENTED' : 'UPSTREAM_CONTRACT_UNVERIFIED'); };
  return Object.freeze({
    id: 'remote',
    contractVersion: ADAPTER_CONTRACT_VERSION,
    upstreamVersion: config?.apiVersion ?? null,
    capabilities: new Set(),
    async health() { return { status: 'fail', detail: { code: verified ? 'ADAPTER_NOT_IMPLEMENTED' : 'UPSTREAM_CONTRACT_UNVERIFIED', mode: 'remote' } }; },
    createDraft: unavailable, submit: unavailable, withdraw: unavailable, startReview: unavailable, readStatus: unavailable, recordEvent: unavailable,
  });
}

/** Choose the adapter from validated configuration. There is no implicit fallback between modes. */
export function selectAdapter(secureIntakeConfig) {
  if (secureIntakeConfig?.mode === 'local') return createLocalAdapter();
  if (secureIntakeConfig?.mode === 'remote') return createRemoteAdapter(secureIntakeConfig);
  throw new AdapterError('ADAPTER_MODE_INVALID');
}

/** Readiness check for the operations module. Required only when intake is enabled. */
export function adapterReadinessCheck(adapter, { required }) {
  return { name: 'secureIntake', required, probe: () => adapter.health() };
}
