export type HeardEnvironment = 'local' | 'ci' | 'staging' | 'production';
export declare const ENVIRONMENTS: readonly HeardEnvironment[];
export declare const STORAGE_DRIVERS: readonly ('none' | 'memory' | 'filesystem' | 's3')[];
export declare const SECURE_INTAKE_MODES: readonly ('local' | 'remote')[];
export declare const SCANNER_DRIVERS: readonly ('none' | 'fake' | 'clamd')[];
export interface VariableDoc { readonly required: string | false; readonly secret: boolean; readonly service: string | null; readonly purpose: string; }
export declare const VARIABLES: Readonly<Record<string, VariableDoc>>;
export declare class ConfigError extends Error { readonly problems: string[]; }
export type ObjectStorageConfig =
  | Readonly<{ driver: 'none' | 'memory' }>
  | Readonly<{ driver: 'filesystem'; directory: string | null }>
  | Readonly<{ driver: 's3'; endpoint: string | null; region?: string | undefined; bucket?: string | undefined; accessKeyId?: string | undefined; secretAccessKey?: string | undefined }>;
export type ScannerConfig = Readonly<{ driver: 'none' | 'fake' }> | Readonly<{ driver: 'clamd'; host: string | null; port: number }>;
export type SecureIntakeConfig = Readonly<{ mode: 'local' }> | Readonly<{ mode: 'remote'; url: string | null; apiVersion: string | null; token: string | null }>;
export interface HeardConfig {
  readonly environment: HeardEnvironment;
  readonly deployed: boolean;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly publicOrigin: string | null;
  readonly release: string | null;
  readonly port: number;
  readonly database: Readonly<{ url: string; poolMax: number; migrateOnStart: boolean }> | null;
  readonly operationsToken: string | null;
  readonly intake: Readonly<{ enabled: boolean }>;
  readonly secrets: Readonly<{ sessionSecret: Buffer | null; dataKey: Buffer | null; dataKeyId: string }>;
  readonly secureIntake: SecureIntakeConfig;
  readonly objectStorage: ObjectStorageConfig;
  readonly scanner: ScannerConfig;
}
export declare function loadConfig(env?: Record<string, string | undefined>): HeardConfig;
export declare function describeConfig(config: HeardConfig): Record<string, unknown>;
