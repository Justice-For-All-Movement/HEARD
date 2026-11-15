import type pg from 'pg';
export interface QueryResultLike { rows: Array<Record<string, unknown>>; rowCount?: number | null; }
export interface QueryClient { query(sql: string, params?: unknown[]): Promise<QueryResultLike>; }
export declare function migrate(client: QueryClient, directory: string | URL, options?: { targetVersion?: number }): Promise<number[]>;
export declare const migrationsDirectory: string;
export declare const LATEST_MIGRATION: number;
export declare const SCOPED_ROLES: readonly ('heard_api' | 'heard_job_worker' | 'heard_public_projector' | 'heard_operator')[];
export declare function isUuid(value: unknown): value is string;
export declare function createPool(database: { url: string; poolMax?: number } | null, options?: { max?: number }): pg.Pool;
export declare function withTransaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T>;
export interface Scope { role?: 'heard_api' | 'heard_job_worker' | 'heard_public_projector' | 'heard_operator'; subjectId?: string | null; settings?: Record<string, string>; }
export declare function withScope<T>(pool: pg.Pool, scope: Scope, fn: (client: pg.PoolClient) => Promise<T>): Promise<T>;
export declare function bindEnvironment(client: QueryClient, environment: string): Promise<string>;
export interface ProbeResult { status: 'ok' | 'not_configured' | 'disabled' | 'fail'; detail?: Record<string, unknown>; }
export declare function probeDatabase(pool: pg.Pool, options: { environment: string }): Promise<ProbeResult>;
