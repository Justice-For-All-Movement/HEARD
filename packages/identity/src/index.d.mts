import type pg from 'pg';
import type { QueryClient } from '@heard/database';
export declare const SESSION_ABSOLUTE_MS: number;
export declare const SESSION_IDLE_MS: number;
export declare const STAFF_SESSION_ABSOLUTE_MS: number;
export declare class IdentityError extends Error { readonly code: string; }
export declare function verifier(secret: Buffer, purpose: string, value: string): string;
export declare function newSessionToken(): string;
export declare function isWellFormedSessionToken(value: unknown): value is string;
export declare function newRecoveryCode(): string;
export declare function normalizeRecoveryCode(input: unknown): string | null;
export declare function aliasKey(name: string): string;
export declare function validatePublicPseudonym(value: unknown): { alias: string; key: string };
export declare const PRIVACY_CHOICE_LABELS: Readonly<Record<'named' | 'pseudonymous' | 'private', string>>;
export type Assurance = 'anonymous_recovery' | 'account' | 'staff_mfa';
export interface Session { sessionId: string; subjectId: string; assurance: Assurance; expiresAt: Date; }
export interface SecretOptions { secret: Buffer; now?: Date; }
export declare function startAnonymous(pool: pg.Pool, options: SecretOptions): Promise<{ subjectId: string; recoveryCode: string; token: string; expiresAt: Date }>;
export declare function resolveSession(pool: pg.Pool, token: unknown, options: SecretOptions): Promise<Session | null>;
export declare function redeemRecovery(pool: pg.Pool, code: unknown, options: SecretOptions & { presentedToken?: string | null }): Promise<{ subjectId: string; recoveryCode: string; token: string; expiresAt: Date }>;
export declare function rotateRecoveryCode(pool: pg.Pool, session: Session, options: SecretOptions): Promise<{ recoveryCode: string }>;
export declare function endSession(pool: pg.Pool, session: Session, options?: { now?: Date; allSessions?: boolean }): Promise<void>;
export declare function getProfile(pool: pg.Pool, session: Session): Promise<{ alias: string | null; language: string }>;
export declare function setProfile(pool: pg.Pool, session: Session, input: { alias?: string | null; language?: string }): Promise<{ alias: string | null; language: string }>;
export declare function activeStaffRoles(client: QueryClient, subjectId: string, now?: Date): Promise<string[]>;
export declare function provisionStaff(pool: pg.Pool, input: { subjectId?: string; role: 'reviewer' | 'editor' | 'safety' | 'administrator'; purpose: string; expiresAt: Date; grantedBy?: string | null }): Promise<string>;
export declare function startStaffSession(pool: pg.Pool, subjectId: string, options: SecretOptions & { mfaVerified: boolean }): Promise<{ token: string; expiresAt: Date }>;
export declare function audit(client: QueryClient, actorId: string | null, action: string, outcome: 'allow' | 'deny', options?: { caseId?: string | null; metadata?: Record<string, unknown> }): Promise<void>;
export declare function createRateLimiter(options: { limit: number; windowMs: number; secret?: Buffer | null; maxKeys?: number }): { check(rawKey: string, now?: number): { allowed: boolean; retryAfterMs: number } };
