import type { QueryClient } from '@heard/database';
export declare const ADAPTER_CONTRACT_VERSION: string;
export type Capability = 'case.create_draft' | 'case.submit' | 'case.withdraw' | 'case.read_status' | 'case.record_event' | 'case.transition_review' | 'case.assign_reviewer' | 'case.helper_grant';
export declare const CAPABILITIES: readonly Capability[];
export declare const VERIFIED_UPSTREAM_VERSIONS: readonly string[];
export type CaseKind = 'question' | 'experience' | 'support';
export type CaseState = 'draft' | 'submitted' | 'review' | 'closed' | 'withdrawn';
export declare const CASE_KINDS: readonly CaseKind[];
export declare const CASE_STATES: readonly CaseState[];
export declare const CASE_TRANSITIONS: Readonly<Record<CaseState, readonly CaseState[]>>;
export declare function canTransition(from: string, to: string): boolean;
export type EventType = 'case_created' | 'case_submitted' | 'case_withdrawn' | 'review_started' | 'case_closed' | 'info_requested';
export declare const EVENT_TYPES: readonly EventType[];
export declare class AdapterError extends Error { readonly code: string; }
export declare function sanitizeEventMetadata(metadata?: Record<string, unknown>): Record<string, string | number>;
export interface CaseStatus { caseId: string; status: CaseState; kind?: CaseKind; updatedAt?: Date; }
export interface SecureIntakeAdapter {
  readonly id: 'local' | 'remote';
  readonly contractVersion: string;
  readonly upstreamVersion: string | null;
  readonly capabilities: ReadonlySet<Capability>;
  health(): Promise<{ status: 'ok' | 'fail'; detail?: Record<string, unknown> }>;
  createDraft(client: QueryClient, input: { caseId: string; subjectId: string; kind: CaseKind }): Promise<CaseStatus>;
  submit(client: QueryClient, input: { caseId: string; actorId: string; policyVersion: string }): Promise<CaseStatus>;
  withdraw(client: QueryClient, input: { caseId: string; actorId: string }): Promise<CaseStatus>;
  startReview(client: QueryClient, input: { caseId: string; actorId: string }): Promise<CaseStatus>;
  readStatus(client: QueryClient, input: { caseId: string }): Promise<CaseStatus>;
  recordEvent(client: QueryClient, input: { caseId: string; actorId?: string | null; type: EventType; metadata?: Record<string, unknown> }): Promise<void>;
}
export declare function requireCapability(adapter: SecureIntakeAdapter, capability: Capability): void;
export declare function createLocalAdapter(): SecureIntakeAdapter;
export declare function createRemoteAdapter(config: { apiVersion?: string | null; url?: string | null }, options?: { verifiedVersions?: readonly string[] }): SecureIntakeAdapter;
export declare function selectAdapter(config: { mode: 'local' | 'remote'; apiVersion?: string | null; url?: string | null }): SecureIntakeAdapter;
export declare function adapterReadinessCheck(adapter: SecureIntakeAdapter, options: { required: boolean }): { name: string; required: boolean; probe: () => Promise<{ status: 'ok' | 'fail'; detail?: Record<string, unknown> }> };
