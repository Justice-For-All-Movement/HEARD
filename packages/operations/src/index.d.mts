export declare const LOG_FIELD_ALLOWLIST: ReadonlySet<string>;
export declare function redactFields(fields?: Record<string, unknown>): Record<string, unknown>;
export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}
export declare function createLogger(options?: { level?: string; sink?: (line: string) => void; base?: Record<string, unknown> }): Logger;
export declare function errorCode(error: unknown): string;
export declare function sanitizedError(): { code: 'SERVICE_UNAVAILABLE'; message: string };
export declare function liveness(options?: { release?: string | null }): { status: 'alive'; release: string | null; readiness: string };
export type ProbeStatus = 'ok' | 'not_configured' | 'disabled' | 'fail';
export interface ReadinessCheck { name: string; required: boolean; probe: () => Promise<{ status: ProbeStatus; detail?: Record<string, unknown> }>; }
export interface ReadinessAssessment { ready: boolean; components: Record<string, { required: boolean; status: ProbeStatus; detail?: Record<string, unknown> }>; }
export declare function assessReadiness(checks: ReadinessCheck[], options?: { timeoutMs?: number }): Promise<ReadinessAssessment>;
export declare function publicReadiness(assessment: ReadinessAssessment): { status: 'ready' | 'not_ready' };
export declare function operatorAuthorized(authorizationHeader: string | null | undefined, configuredToken: string | null): boolean;
