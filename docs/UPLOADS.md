# Resumable private uploads (HEARD-12)

Available only when `HEARD_INTAKE_ENABLED=true` **and** `HEARD_OBJECT_STORAGE_DRIVER` is configured (`s3` for Backblaze B2 in staging/production; `memory`/`filesystem` only in local/ci). Otherwise every upload route is 404.

## Flow

1. `POST /api/v1/drafts/{caseId}/uploads {type, size, sha256}` — owner of a **draft** case only. The type must be on the allowlist; the size within its ceiling; the full-file SHA-256 is declared up front. No filename or other user text is accepted or stored. Returns `uploadId`, `chunkSize` (5 MiB) and `partCount`. Sessions expire after 24 h.
2. `PUT /api/v1/uploads/{id}/parts/{n}` with `application/octet-stream` — each part must be exactly `chunkSize` bytes (the last part the remainder). Parts can arrive in any order and be re-sent; `GET /api/v1/uploads/{id}` lists received parts for resuming after interruption.
3. `POST /api/v1/uploads/{id}/complete` — the object is assembled in storage, re-read and accepted only if its size and SHA-256 equal the declaration; otherwise the bytes are deleted and the session is `rejected`. Accepted objects are recorded in `heard_private_objects` as `quarantined` under an opaque `quarantine/<uuid>` key.
4. `DELETE /api/v1/uploads/{id}` aborts. `expireUploadSessions` (job role, declared purpose) expires abandoned sessions and releases their storage.

| Group | Types | Max size | Per draft |
|---|---|---|---|
| document | image/jpeg, image/png, application/pdf | 25 MiB | 10 |
| video | video/mp4, video/quicktime | 300 MiB | 1 |
| audio | audio/mpeg, audio/mp4 | 100 MiB | 2 |

## Storage boundary

`packages/storage` offers no public-URL operation. The S3 adapter signs each request with AWS Signature V4 (verified against AWS's published example), uses path-style requests to a private bucket and never surfaces provider response bodies in errors. Uploads are proxied through HEARD rather than pre-signed browser URLs, so no bearer URL can leak into browser history, logs or referrers; the trade-off is that bytes transit the web service (bandwidth/cost to monitor). B2 bucket privacy, lifecycle rules for unfinished multipart uploads and server-side encryption settings are configured by the deploying lead (HEARD-46).

Quarantined objects are never served; HEARD-13 adds content verification, malware scanning and the only path to `cleared`.
