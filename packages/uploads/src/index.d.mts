import type pg from 'pg';
import type { QueryClient } from '@heard/database';
import type { Session } from '@heard/identity';
import type { ObjectStorage } from '@heard/storage';
export declare const CHUNK_SIZE: number;
export declare const SESSION_TTL_MS: number;
export type MediaType = 'image/jpeg' | 'image/png' | 'application/pdf' | 'video/mp4' | 'video/quicktime' | 'audio/mpeg' | 'audio/mp4';
export declare const MEDIA_TYPES: Readonly<Record<MediaType, { group: 'document' | 'video' | 'audio'; maxBytes: number }>>;
export declare const GROUP_QUOTAS: Readonly<Record<'document' | 'video' | 'audio', number>>;
export declare class UploadError extends Error { readonly code: string; readonly field?: string; }
export declare function partLength(session: { partCount: number; chunkSize: number; declaredSize: number }, partNumber: number): number | null;
export declare function validateDeclaration(input: { type: unknown; size: unknown; sha256: unknown }): { type: MediaType; size: number; sha256: string; group: string; partCount: number };
export interface UploadService {
  start(session: Session, caseId: string, declaration: { type: unknown; size: unknown; sha256: unknown }, options?: { now?: Date }): Promise<{ uploadId: string; chunkSize: number; partCount: number; expiresAt: Date }>;
  putPart(session: Session, uploadId: string, partNumber: number, bytes: Buffer, options?: { now?: Date }): Promise<{ partNumber: number; sha256: string }>;
  status(session: Session, uploadId: string): Promise<{ uploadId: string; state: string; partCount: number; chunkSize: number; receivedParts: number[]; objectId: string | null; rejection: string | null; expiresAt: Date }>;
  complete(session: Session, uploadId: string, options?: { now?: Date }): Promise<{ objectId: string; state: 'quarantined'; sha256: string; size: number }>;
  abort(session: Session, uploadId: string, options?: { now?: Date }): Promise<{ uploadId: string; state: 'aborted' }>;
}
export declare function createUploadService(deps: { pool: pg.Pool; storage: ObjectStorage | null; onObjectQuarantined?: (client: QueryClient, input: { objectId: string; caseId: string; actorId: string }) => Promise<void> }): UploadService;
export declare function expireUploadSessions(pool: pg.Pool, storage: ObjectStorage): Promise<number>;
