export declare class StorageError extends Error { readonly code: string; }
export declare function assertKey(key: unknown): asserts key is string;
export declare function quarantineKey(): string;
export declare const EMPTY_SHA256: string;
export interface ObjectStorage {
  readonly driver: 'memory' | 'filesystem' | 's3';
  health(): Promise<{ status: 'ok' | 'fail'; detail?: Record<string, unknown> }>;
  createMultipart(key: string): Promise<string>;
  uploadPart(key: string, uploadId: string, partNumber: number, bytes: Uint8Array): Promise<string>;
  completeMultipart(key: string, uploadId: string, parts: { partNumber: number; etag: string }[]): Promise<void>;
  abortMultipart(key: string, uploadId: string): Promise<void>;
  getObject(key: string): AsyncIterable<Buffer>;
  deleteObject(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}
export declare function createMemoryStorage(): ObjectStorage & { _objects: Map<string, Buffer> };
export declare function createFilesystemStorage(directory: string): ObjectStorage;
export interface S3Settings { endpoint: string; region: string; bucket: string; accessKeyId: string; secretAccessKey: string; }
export declare function createS3Storage(settings: S3Settings, options?: { fetchImpl?: typeof fetch }): ObjectStorage;
export declare function signV4(input: { method: string; url: URL; headers?: Record<string, string>; payloadSha256: string; region: string; accessKeyId: string; secretAccessKey: string; date?: Date; service?: string }): Record<string, string>;
export declare function selectStorage(config: { driver: string; [key: string]: unknown } | null | undefined): ObjectStorage | null;
export declare function digestObject(storage: ObjectStorage, key: string, options: { maxBytes: number }): Promise<{ sha256: string; size: number; head: Buffer }>;
