# Durable job framework (HEARD-15)

`packages/jobs` runs background work on the existing `heard_jobs` table (no Redis or extra services). Migration `0012_durable_jobs.sql` adds payloads, cancellation and per-kind worker scoping. Malware scanning (HEARD-13) now runs on it; media processing (HEARD-16+) will add kinds.

| Property | How |
|---|---|
| Transactional, deduplicated enqueue | `enqueue(client, {kind, caseId, objectId?, dedupeKey, payload?, maxAttempts?})` runs in the caller's transaction; a repeated dedupe key returns the existing job. At most 50 active jobs per case (cost bound). |
| Leasing | `FOR UPDATE SKIP LOCKED`; worker role `heard_job_worker` with `heard.job_purpose = <kind>`; RLS confines a worker to its kind. |
| Killed workers | Leases expire; another worker resumes. Exhausted jobs whose lease expired are dead-lettered (`LEASE_EXPIRED`). |
| No double effects | Handlers return a `commit` callback that runs only while the worker still owns the lease (compare-and-set); late, cancelled or duplicate runs apply nothing. A failing commit releases the job for retry. |
| Budgets | Each run gets an `AbortSignal` and wall-clock budget (≤ lease); timeouts retry. Handlers enforce byte ceilings (see QUARANTINE.md). |
| Retry / dead letter | `JobError(code)` retries with backoff; `permanent(code)` or exhausted attempts set `failed` with the code. Unknown exceptions become `JOB_HANDLER_ERROR` (messages are never stored). Poison jobs do not block others. |
| Status and cancellation | `GET /api/v1/my/cases/{id}/jobs` (owner: kind, state, attempts, error code; no payloads or worker identities); `POST /api/v1/jobs/{id}/cancel` for queued or running jobs on the caller's own case. Cancelling a scan leaves the file quarantined permanently. |
| Payloads | Small allowlisted scalars only (no narrative, names or URLs). |

Run workers with `npm run worker` (see DEPLOYMENT_RENDER.md). Isolated object credentials per job kind are a deployment property (separate B2 keys per worker service) for HEARD-46.
