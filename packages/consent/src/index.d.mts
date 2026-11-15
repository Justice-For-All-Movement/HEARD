import type { QueryClient } from '@heard/database';
import type { Session } from '@heard/identity';
export type Purpose = 'private_processing' | 'contact' | 'helper_access' | 'publication' | 'identity_display' | 'archive_replication';
export interface ConsentPolicy { readonly version: string; readonly title: string; readonly text: string; readonly recipients: readonly string[]; readonly scopeKeys: readonly string[]; readonly sha256: string; }
export declare const CONSENT_POLICIES: Readonly<Record<Purpose, ConsentPolicy>>;
export declare const PURPOSES: readonly Purpose[];
export declare class ConsentError extends Error { readonly code: string; readonly field?: string; }
export interface ConsentScope { recipients?: string[]; assets?: string[]; fields?: string[]; mode?: 'named' | 'pseudonymous' | 'private'; channels?: string[]; }
export declare function normalizeScope(purpose: string, scope?: unknown): ConsentScope;
export interface ConsentEvent { sequence: number; purpose: string; decision: 'grant' | 'revoke'; policyVersion: string; policyTextSha256: string | null; scope?: ConsentScope; expiresAt?: Date | null; recordedAt?: Date; }
export type ConsentStatus = 'granted' | 'not_granted' | 'revoked' | 'stale' | 'expired';
export type EffectiveConsents = Record<Purpose, { status: ConsentStatus; scope?: ConsentScope; policyVersion?: string }>;
export declare function effectiveConsents(events: ConsentEvent[], options?: { now?: Date }): EffectiveConsents;
export declare function consentCovers(effective: EffectiveConsents, purpose: Purpose, target?: { recipientId?: string; assetIds?: string[]; fields?: string[] }): boolean;
export interface PreviewItem { purpose: Purpose; title: string; status: ConsentStatus; effective: boolean; recipients: readonly string[]; scope: ConsentScope; summary: string; }
export declare function disclosurePreview(effective: EffectiveConsents): PreviewItem[];
export declare function loadConsents(client: QueryClient, caseId: string): Promise<ConsentEvent[]>;
export declare function caseConsentState(client: QueryClient, session: Session, caseId: string, options?: { now?: Date }): Promise<{ effective: EffectiveConsents; preview: PreviewItem[] }>;
export declare function recordConsent(client: QueryClient, session: Session, caseId: string, input: { purpose: string; decision: string; policyVersion?: string; scope?: unknown; expiresAt?: Date | null }, options?: { now?: Date }): Promise<{ effective: EffectiveConsents; preview: PreviewItem[] }>;
export declare function requireConsent(client: QueryClient, caseId: string, purpose: Purpose, target?: { recipientId?: string; assetIds?: string[]; fields?: string[] }, options?: { now?: Date }): Promise<{ status: ConsentStatus; scope?: ConsentScope }>;
export declare function publicPolicies(): Array<{ purpose: Purpose; version: string; title: string; text: string; recipients: readonly string[]; scopeKeys: readonly string[]; sha256: string }>;
