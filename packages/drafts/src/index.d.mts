import type pg from 'pg';
import type { Session } from '@heard/identity';
import type { Answers, Kind } from '@heard/intake';
import type { SecureIntakeAdapter } from '@heard/secure-intake';
export declare const DRAFT_TTL_MS: number;
export declare const MAX_OPEN_DRAFTS: number;
export declare class DraftError extends Error { readonly code: string; readonly field?: string; }
export interface DataKey { key: Buffer; keyId: string; keyring?: Record<string, Buffer>; }
export declare function encryptAnswers(key: DataKey, caseId: string, schemaVersion: string, answers: Answers): string;
export declare function decryptAnswers(keys: Record<string, Buffer>, caseId: string, schemaVersion: string, ciphertext: string): Answers;
export declare function newReceiptReference(): string;
export declare function isValidIdempotencyKey(value: unknown): value is string;
export interface Receipt { reference: string; submittedAt: Date; status: 'submitted'; replayed: boolean; nextSteps: string; }
export interface DraftView { caseId: string; kind: Kind; status: string; revision: number; schemaVersion: string; answers: Answers; updatedAt: Date; expiresAt: Date | null; receipt: { reference: string; submittedAt: Date } | null; }
export interface DraftService {
  create(session: Session, input: { kind: string }, options?: { now?: Date }): Promise<{ caseId: string; kind: Kind; revision: number; expiresAt: Date }>;
  get(session: Session, caseId: string): Promise<DraftView>;
  save(session: Session, caseId: string, input: { revision: number; answers: unknown }, options?: { now?: Date }): Promise<{ caseId: string; revision: number; answers: Answers }>;
  submit(session: Session, caseId: string, input: { revision: number; idempotencyKey: string }): Promise<Receipt>;
  withdraw(session: Session, caseId: string): Promise<{ caseId: string; status: 'withdrawn'; answersDeleted: boolean }>;
  listMine(session: Session): Promise<Array<{ caseId: string; kind: Kind; status: string; updatedAt: Date; reference: string | null }>>;
}
export declare function createDraftService(deps: { pool: pg.Pool; adapter: SecureIntakeAdapter; crypto: DataKey; secret: Buffer }): DraftService;
export declare function purgeExpiredDrafts(pool: pg.Pool): Promise<number>;
