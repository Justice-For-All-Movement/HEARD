import type pg from 'pg';
import type { QueryClient } from '@heard/database';
import type { ObjectStorage } from '@heard/storage';
export declare class ScanError extends Error { readonly code: string; }
export declare function detectType(head: Uint8Array | null | undefined): string | null;
export declare function inspectObject(chunks: AsyncIterable<Buffer>, options: { maxBytes: number; declaredType: string }): Promise<{ sha256: string; size: number; detectedType: string | null; finding: string | null }>;
export interface ScanResult { verdict: 'clean' | 'infected'; engine: string; signature?: string; }
export interface Scanner { readonly engine: string | null; health(): Promise<{ status: 'ok' | 'fail'; detail?: Record<string, unknown> }>; scan(chunks: AsyncIterable<Buffer>): Promise<ScanResult>; }
export declare function createNoScanner(): Scanner;
export declare const EICAR: string;
export declare function createFakeScanner(options?: { fail?: boolean }): Scanner;
export declare function createClamdScanner(options: { host: string; port?: number; timeoutMs?: number }): Scanner;
export declare function selectScanner(config: { driver: string; host?: string | null; port?: number } | null | undefined): Scanner;
export declare const RETRY_BACKOFF_MS: readonly number[];
export declare function enqueueScan(client: QueryClient, input: { objectId: string; caseId: string }): Promise<void>;
export interface Outcome { state: 'cleared' | 'rejected'; reason: string | null; verdict?: 'clean' | 'infected'; engine?: string; detectedType: string | null; }
export declare function evaluateObject(input: { storage: ObjectStorage; scanner: Scanner; object: { storage_ref: string; checksum_sha256: string; declared_type: string; size_bytes: number | string } }): Promise<Outcome>;
export declare function processScanJobs(pool: pg.Pool, options: { storage: ObjectStorage; scanner: Scanner; workerId?: string; limit?: number; leaseMs?: number }): Promise<Array<{ jobId: string; objectId: string; state: string; reason: string | null }>>;
