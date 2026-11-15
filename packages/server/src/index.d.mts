import type { HeardConfig } from '@heard/config';
import type { Logger, ReadinessCheck } from '@heard/operations';
export declare const SECURITY_HEADERS: Readonly<Record<string, string>>;
export declare class HttpError extends Error { readonly code: string; readonly retryAfter?: number; readonly fields?: Record<string, string>; constructor(code: string, options?: { retryAfter?: number; fields?: Record<string, string> }); }
export declare function json(status: number, body: unknown, headers?: Record<string, string>): Response;
export declare function errorResponse(code: string, options?: { retryAfter?: number; fields?: Record<string, string> }): Response;
export interface Route { method: string; pattern: RegExp; label?: string; handler: (request: Request, match: RegExpMatchArray, context: AppContext) => Promise<Response> | Response; }
export interface AppContext { config: HeardConfig; logger: Logger; getPool: () => unknown; modules: AppModule[]; adapter?: import('@heard/secure-intake').SecureIntakeAdapter; requireSession?: (request: Request) => Promise<import('@heard/identity').Session>; storage?: import('@heard/storage').ObjectStorage | null; onObjectQuarantined?: (client: import('@heard/database').QueryClient, input: { objectId: string; caseId: string }) => Promise<void>; }
export interface AppModule { routes: Route[]; readinessChecks?: () => ReadinessCheck[]; }
export interface HeardApp { config: HeardConfig; context: AppContext; use(module: AppModule): void; handle(request: Request): Promise<Response>; close(): Promise<void>; }
export declare function createApp(options?: { config?: HeardConfig; env?: Record<string, string | undefined>; pool?: unknown; logger?: Logger; extraChecks?: ReadinessCheck[] }): HeardApp;
export declare function createHeardServer(options?: Parameters<typeof createApp>[0] & { adapter?: import('@heard/secure-intake').SecureIntakeAdapter; storage?: import('@heard/storage').ObjectStorage | null }): HeardApp;
