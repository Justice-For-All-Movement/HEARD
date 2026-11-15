export declare const INTAKE_SCHEMA_VERSION: string;
export type Kind = 'question' | 'experience' | 'support';
export declare const KINDS: readonly Kind[];
export type Classification = 'C1' | 'C2' | 'C3';
export declare const CLASSIFICATIONS: readonly Classification[];
export interface Option { readonly value: string; readonly label: string; }
export declare const CATEGORY_OPTIONS: readonly Option[];
export declare const HELP_OPTIONS: readonly Option[];
export declare const DATE_PRECISION: readonly string[];
export declare const LOCATION_PRECISION: readonly string[];
export declare const IDENTITY_MODES: readonly ('private' | 'pseudonymous' | 'named')[];
export interface FieldDef {
  readonly id: string;
  readonly type: 'text' | 'textarea' | 'choice' | 'multi' | 'partial_date';
  readonly label: string;
  readonly hint?: string;
  readonly options?: readonly Option[];
  readonly maxLength?: number;
  readonly minLength?: number;
  readonly maxItems?: number;
  readonly required: boolean;
  readonly requiredFor: readonly Kind[];
  readonly classification: Classification;
}
export interface StepDef { readonly id: string; readonly title: string; readonly fields: readonly FieldDef[]; readonly note?: string; }
export declare const STEPS: readonly StepDef[];
export declare const FIELDS: Readonly<Record<string, FieldDef & { readonly step: string }>>;
export declare class IntakeValidationError extends Error { readonly code: 'INTAKE_INVALID'; readonly errors: Record<string, string>; readonly field: string; }
export type Answers = Record<string, string | string[]>;
export declare function validateAnswers(input: unknown, options?: { partial?: boolean }): Answers;
export declare function classify(answers: Answers): Record<string, Classification>;
export declare function publicSchema(): { version: string; steps: readonly StepDef[] };
