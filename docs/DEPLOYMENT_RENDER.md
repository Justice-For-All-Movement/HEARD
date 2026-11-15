# Deploying HEARD on Render (HEARD-06)

Status: deployable engineering service. A deployed URL is not evidence that private intake is safe to open. Intake stays disabled (`HEARD_INTAKE_ENABLED=false`) until the release gates in `docs/DEVELOPMENT_PLAN.md` §16 are met.

## Live deployment (recorded 2026-11-15)

| Item | Value |
|---|---|
| URL | https://heard-web-ug5f.onrender.com |
| Render service | `heard-web` (free plan, native Node, auto-deploy from `main`) |
| Database | dedicated Neon PostgreSQL 16 database (`DATABASE_URL`, migrations on start) |
| Configured secrets | session secret, data encryption key, operations token (values held in Render only) |
| Intake | `HEARD_INTAKE_ENABLED=false` |

Created and configured by the deploying lead, not by the implementing agent. Because the service auto-deploys from `main`, every PR must keep `main` deployable: the `Render deployability` workflow runs the exact Render build command with `NODE_ENV=production`, then starts the service with `npm start` with no database and with PostgreSQL 16 owned by a non-superuser CREATEROLE login (as on Neon), and requires `/api/health` and `/api/ready` to pass. The first deploy (`cd4208b`) failed at build because `NODE_ENV=production` made `npm ci` omit devDependencies; the build command now includes `--include=dev` (and `.npmrc` sets `include=dev`).

## What runs

One Render **Node web service** (`render.yaml`, service `heard-web`) running the Next.js production server:

| Step | Command |
|---|---|
| Build | `npm ci --ignore-scripts --include=dev && npm run build` (Render sets `NODE_ENV=production`, which would otherwise omit the TypeScript toolchain `next build` needs; `.npmrc` also sets `include=dev`) |
| Start | `npm start` (runs `scripts/start.mjs`) |
| Health check (liveness) | `GET /api/health` → `200 {"status":"alive","release":…}` |
| Readiness | `GET /api/ready` → `200 {"status":"ready"}` or `503 {"status":"not_ready"}` |
| Operator detail | `GET /api/ready?detail=1` with `Authorization: Bearer $HEARD_OPERATIONS_TOKEN` (404 otherwise) |

`scripts/start.mjs` validates the whole environment before listening and exits with code 78 on any invalid or unsafe combination, printing variable names only (never values). When `DATABASE_URL` is set and `HEARD_MIGRATE_ON_START=true`, it applies the checksum-bound migrations under an advisory lock and binds the database to `HEARD_ENV` before serving; a failed migration stops the deploy.

Node 22 is pinned by `.nvmrc`, `engines` and `NODE_VERSION` in the Blueprint.

## Minimal deployment (no external credentials)

Apply the Blueprint and leave every `sync: false` value blank. The service serves the public shell, `/api/health` and `/api/ready` (ready, because no private dependency is configured). Nothing private is collected.

## Adding the database (Neon)

1. Create an **isolated** Neon project/database for HEARD (never reuse another application's database or role).
2. Set `DATABASE_URL` to its pooled or direct connection string **with `sslmode=require`**. Staging/production refuse a non-TLS URL.
3. Keep `HEARD_MIGRATE_ON_START=true` (or run `npm run db:migrate` once with the same environment). The first run binds the database to `HEARD_ENV`; a staging service pointed at the production database (or vice versa) then reports `ENVIRONMENT_MISMATCH` and is not ready.
4. The connecting role must be able to `SET ROLE heard_api` (migrations grant this to the migrating role). If the runtime uses a different login role than the migrator, run `GRANT heard_api TO <runtime_role>` once.

Readiness then requires the database to be reachable, migrated to exactly this release's version and bound to the same environment.

## Enabling private intake (later, behind release gates)

Set `HEARD_INTAKE_ENABLED=true` only together with `DATABASE_URL`, `HEARD_SESSION_SECRET`, `HEARD_DATA_ENCRYPTION_KEY` and a real `HEARD_PUBLIC_ORIGIN`. Generate each secret independently:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Back up `HEARD_DATA_ENCRYPTION_KEY` in the organization's secret store: losing it makes encrypted drafts unrecoverable. Rotating it requires a new `HEARD_DATA_ENCRYPTION_KEY_ID` and a re-encryption job (not yet implemented).

## Background worker (uploads)

Uploads (HEARD-12/13) need private storage (`HEARD_OBJECT_STORAGE_DRIVER=s3` + `HEARD_S3_*`) and a separate worker process running `npm run worker` with the same `DATABASE_URL`, storage and scanner settings (`HEARD_SCANNER_DRIVER=clamd`, `HEARD_CLAMD_HOST`). A commented Render background-worker definition is at the end of `render.yaml`. Without a scanner, uploads stay quarantined and are never served. ClamAV itself (e.g. a private Render service running clamd) is not defined here.

## Environment variables

Required-ness is enforced by `packages/config`. Secrets are marked; never commit their values.

| Variable | Required | Secret | External service | Purpose |
|---|---|---|---|---|
| `HEARD_ENV` | production deployments | no | — | Deployment environment name (local, ci, staging, production). Bound to the database on first migration to prevent cross-connection. |
| `PORT` | set by Render | no | Render | HTTP listen port. |
| `HEARD_PUBLIC_ORIGIN` | when intake is enabled outside local/ci | no | — | Canonical https origin used for same-origin (CSRF) checks on mutating requests. |
| `HEARD_BUILD_SHA` | optional | no | — | Release commit reported by /api/health. Falls back to RENDER_GIT_COMMIT. |
| `HEARD_LOG_LEVEL` | optional | no | — | debug, info, warn or error (default info). Logs are structured and redacted. |
| `DATABASE_URL` | for intake and readiness of private services | yes | Neon PostgreSQL | PostgreSQL connection string for the isolated HEARD database (sslmode=require for Neon). |
| `HEARD_DATABASE_POOL_MAX` | optional | no | — | Maximum pooled connections (default 5). |
| `HEARD_MIGRATE_ON_START` | optional | no | — | When true, the start script applies checksum-bound migrations before serving. |
| `HEARD_OPERATIONS_TOKEN` | optional | yes | — | Bearer token for detailed readiness (/api/ready?detail=1). Without it, only coarse status is public. |
| `HEARD_INTAKE_ENABLED` | optional | no | — | Feature flag for anonymous sessions, drafts and private submission (default false). |
| `HEARD_SESSION_SECRET` | when intake is enabled | yes | — | At least 32 random bytes (base64/hex) keying session, recovery and receipt verifiers. |
| `HEARD_DATA_ENCRYPTION_KEY` | when intake is enabled | yes | — | Exactly 32 random bytes (base64) for AES-256-GCM field encryption of draft answers. |
| `HEARD_DATA_ENCRYPTION_KEY_ID` | optional | no | — | Identifier recorded with each ciphertext to support key rotation (default k1). |
| `HEARD_SECURE_INTAKE_MODE` | optional | no | Secure Intake & Case Workflow Engine | local (HEARD-owned PostgreSQL adapter, default) or remote (disabled until an upstream contract is verified). |
| `HEARD_SECURE_INTAKE_URL` | when mode is remote | no | Secure Intake & Case Workflow Engine | https base URL of a verified engine deployment. |
| `HEARD_SECURE_INTAKE_API_VERSION` | when mode is remote | no | Secure Intake & Case Workflow Engine | Pinned upstream API version (for example v1). |
| `HEARD_SECURE_INTAKE_TOKEN` | when mode is remote | yes | Secure Intake & Case Workflow Engine | Service credential for the engine. |
| `HEARD_OBJECT_STORAGE_DRIVER` | optional | no | Backblaze B2 (S3-compatible) | none (default), memory (tests), filesystem (local) or s3 (B2/S3-compatible). |
| `HEARD_OBJECT_STORAGE_DIR` | when driver is filesystem | no | — | Private local directory for synthetic objects. |
| `HEARD_S3_ENDPOINT` | when driver is s3 | no | Backblaze B2 | S3-compatible https endpoint, e.g. https://s3.us-west-004.backblazeb2.com. |
| `HEARD_S3_REGION` | when driver is s3 | no | Backblaze B2 | Signing region, e.g. us-west-004. |
| `HEARD_S3_BUCKET` | when driver is s3 | no | Backblaze B2 | Private bucket for quarantined uploads and originals. |
| `HEARD_S3_ACCESS_KEY_ID` | when driver is s3 | yes | Backblaze B2 | Application key ID scoped to the private bucket. |
| `HEARD_S3_SECRET_ACCESS_KEY` | when driver is s3 | yes | Backblaze B2 | Application key scoped to the private bucket. |
| `HEARD_SCANNER_DRIVER` | optional | no | Malware scanner (ClamAV clamd) | none (default: uploads stay quarantined), fake (tests only) or clamd. |
| `HEARD_CLAMD_HOST` | when scanner is clamd | no | ClamAV clamd | Private-network clamd host. |
| `HEARD_CLAMD_PORT` | optional | no | ClamAV clamd | clamd TCP port (default 3310). |

`NODE_ENV`, `NODE_VERSION` and `NEXT_TELEMETRY_DISABLED` are platform settings fixed in `render.yaml`.

## External services summary

| Service | Needed for | Variables | Without it |
|---|---|---|---|
| Render | Hosting the web service | `PORT` (automatic) | — |
| Neon PostgreSQL | Private records, sessions, drafts, readiness | `DATABASE_URL` | Public shell only; intake cannot be enabled |
| Backblaze B2 (S3-compatible) | Private evidence uploads (HEARD-12) | `HEARD_S3_*` | Uploads unavailable |
| ClamAV clamd | Malware scanning (HEARD-13) | `HEARD_CLAMD_*` | Uploads remain quarantined (never promoted) |
| Secure Intake & Case Workflow Engine | Remote case workflow (HEARD-05) | `HEARD_SECURE_INTAKE_*` | Local HEARD-owned adapter is used; remote mode is blocked until the upstream contract is verified |

## Verification after deploy

```sh
curl -fsS https://<host>/api/health
curl -sS https://<host>/api/ready
curl -sS -H "Authorization: Bearer $HEARD_OPERATIONS_TOKEN" "https://<host>/api/ready?detail=1"
```

Record the deployed commit (`release` in `/api/health`), readiness detail and date in `docs/CROSS_ACCOUNT_HANDOFF.md`. Backups, restore drills, monitoring and cost guards remain HEARD-45/46 work.
