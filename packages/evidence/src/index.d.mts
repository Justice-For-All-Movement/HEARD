import type { QueryClient } from '@heard/database';
import type { Session } from '@heard/identity';
import type { ObjectStorage } from '@heard/storage';
export type Operation = 'received' | 'scan_cleared' | 'scan_rejected' | 'downloaded' | 'verified' | 'verification_failed' | 'source_asserted' | 'manifest_exported';
export declare const OPERATIONS: readonly Operation[];
export type Source = 'self_recorded' | 'recorded_by_someone_else' | 'official_record' | 'public_source' | 'unknown';
export declare const SOURCES: readonly Source[];
export declare class EvidenceError extends Error { readonly code: string; readonly field?: string; }
export declare function sanitizeDetail(detail?: Record<string, unknown>): Record<string, string>;
export type ActorKind = 'contributor' | 'staff' | 'helper' | 'service';
export declare function actorKind(session: Session, caseOwnerId: string | null): ActorKind;
export declare function recordEvent(client: QueryClient, input: { objectId: string; caseId: string; operation: Operation; actorKind: ActorKind; actorId?: string | null; detail?: Record<string, unknown> }): Promise<void>;
export interface LedgerVerification { valid: boolean; problems: string[]; length: number; head: string | null; events: Array<Record<string, unknown>>; }
export declare function verifyLedger(client: QueryClient, objectId: string): Promise<LedgerVerification>;
export declare function verifyObjectBytes(client: QueryClient, session: Session, storage: ObjectStorage, objectId: string, options?: { now?: Date }): Promise<{ objectId: string; matches: boolean; sha256: string }>;
export declare function assertSource(client: QueryClient, session: Session, objectId: string, input: { source: unknown; captured?: unknown }, options?: { now?: Date }): Promise<{ objectId: string; source: Source; captured: string | null }>;
export declare const MANIFEST_NOTICE: string;
export declare function caseManifest(client: QueryClient, session: Session, caseId: string, options?: { now?: Date }): Promise<Record<string, unknown>>;
