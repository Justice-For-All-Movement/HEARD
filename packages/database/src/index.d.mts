export interface QueryResultLike { rows: Array<Record<string, unknown>>; }
export interface QueryClient { query(sql: string, params?: unknown[]): Promise<QueryResultLike>; }
export declare function migrate(client: QueryClient, directory: string | URL, options?: { targetVersion?: number }): Promise<number[]>;
export declare const migrationsDirectory: URL;
