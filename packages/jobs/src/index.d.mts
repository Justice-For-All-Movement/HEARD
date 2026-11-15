import type pg from 'pg';
import type { QueryClient } from '@heard/database';
export declare const DEFAULT_BACKOFF_MS: readonly number[];
export declare const MAX_ACTIVE_JOBS_PER_CASE: number;
export declare class JobError extends Error { readonly code: string; readonly retryable: boolean; constructor(code: string, options?: { retryable?: boolean }); }
export declare function permanent(code: string): JobError;
export declare function sanitizePayload(payload?: unknown): Record<string, string | number | boolean>;
export declare function enqueue(client: QueryClient, input: { kind: string; caseId: string; objectId?: string | null; dedupeKey: string; payload?: Record<string, unknown>; maxAttempts?: number; availableAt?: Date | null }): Promise<{ jobId: string | null; created: boolean }>;
export interface LeasedJob { id: string; caseId: string; objectId: string | null; payload: Record<string, unknown>; attempts: number; maxAttempts: number; }
export declare function lease(pool: pg.Pool, options: { kind: string; workerId: string; limit?: number; leaseMs?: number; settings?: Record<string, string> }): Promise<LeasedJob[]>;
export interface HandlerResult { commit?: (client: pg.PoolClient) => Promise<void>; }
export declare function runJobs(pool: pg.Pool, options: {
  kind: string;
  handler: (job: LeasedJob, ctx: { signal: AbortSignal; read: <T>(fn: (client: pg.PoolClient) => Promise<T>) => Promise<T> }) => Promise<HandlerResult | void>;
  onFailure?: (client: pg.PoolClient, info: { job: LeasedJob; code: string; final: boolean }) => Promise<void>;
  workerId?: string; limit?: number; leaseMs?: number; timeoutMs?: number; backoffMs?: readonly number[]; settings?: Record<string, string>;
}): Promise<Array<{ jobId: string; objectId: string | null; outcome: string; code: string | null }>>;
export declare function caseJobs(client: QueryClient, caseId: string): Promise<Array<{ jobId: string; kind: string; objectId: string | null; state: string; attempts: number; maxAttempts: number; errorCode: string | null; createdAt: Date; finishedAt: Date | null }>>;
export declare function cancelJob(client: QueryClient, jobId: string): Promise<void>;
