import type pg from 'pg';
import type { QueryClient } from '@heard/database';
import type { Session } from '@heard/identity';
export type Action = 'case.read' | 'case.edit_draft' | 'case.submit' | 'case.withdraw' | 'consent.record' | 'evidence.upload' | 'evidence.read' | 'grant.create' | 'grant.revoke' | 'review.read_case' | 'review.decide' | 'publication.review' | 'identity.reveal';
export declare const ACTIONS: readonly Action[];
export declare const AUDITED_ACTIONS: ReadonlySet<Action>;
export interface Principal { subjectId: string; assurance: string; staffRoles?: string[]; }
export type Resource =
  | { type: 'case'; id: string; ownerId: string; status: string }
  | { type: 'object'; id: string; caseId: string; ownerId: string; caseStatus: string };
export interface Facts {
  now?: Date;
  assignments?: { caseId: string; role: string; expiresAt: Date; revokedAt: Date | null }[];
  grants?: { objectId: string; recipientId: string; action: string; expiresAt: Date; revokedAt: Date | null }[];
  revealApprovals?: { staffSubjectId: string; role: string }[];
}
export interface Decision { readonly allow: boolean; readonly reason: string; }
export declare function decide(principal: Principal | null, action: string, resource: Resource | null, facts?: Facts): Decision;
export declare class AuthorizationError extends Error { readonly code: 'NOT_FOUND'; readonly reason: string; }
export declare function withSession<T>(pool: pg.Pool, session: Session, fn: (client: pg.PoolClient) => Promise<T>): Promise<T>;
export declare function loadPrincipal(client: QueryClient, session: Session, now?: Date): Promise<Required<Principal>>;
export declare function authorizeCase(client: QueryClient, session: Session, action: Action, caseId: string, options?: { now?: Date }): Promise<{ id: string; ownerId: string; status: string; kind: string }>;
export declare function authorizeObject(client: QueryClient, session: Session, action: Action, objectId: string, options?: { now?: Date }): Promise<{ id: string; caseId: string; quarantineState: string }>;
export declare function createGrant(client: QueryClient, session: Session, input: { caseId: string; objectId: string; recipientId: string; action?: 'read' | 'download'; purpose: string; expiresAt: Date; now?: Date }): Promise<string>;
export declare function revokeGrant(client: QueryClient, session: Session, grantId: string, options?: { now?: Date }): Promise<void>;
export declare function assignStaff(pool: pg.Pool, input: { caseId: string; staffSubjectId: string; role: 'reviewer' | 'editor' | 'safety'; purpose: string; expiresAt: Date; assignedBy?: string | null }): Promise<string>;
