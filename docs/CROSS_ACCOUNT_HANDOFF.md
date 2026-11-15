# HEARD — independent-account handoff

**Repository:** https://github.com/Justice-For-All-Movement/HEARD (default branch `main`)  
**Product:** HEARD, an initiative of Justice For All  
**Positioning:** *Your rights. Your voice. Your next step.*  
**Primary specification:** [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) · **PR register:** [../registry/prs.json](../registry/prs.json)  
**Public copy and editorial policy:** [CONTENT_STRATEGY.md](CONTENT_STRATEGY.md) and [../content/site-copy.json](../content/site-copy.json)  
**Last updated:** 2026-11-15

## Product and experience

HEARD brings rights information, practical support, and firsthand experiences together in one place. Its primary services are a rights library, questions and help, experience/evidence preservation, a reviewed public archive, and ways to help others. The homepage has six independent pathways and uses the canonical language from `content/site-copy.json`.

## Status (separate fields — do not conflate)

Live private intake, production readiness for sensitive use, verified secure messaging, a custom domain and Engine Room monitoring have **not been established**.

| Field | State |
|---|---|
| Source implementation | HEARD-01 … HEARD-14 merged (see table). HEARD-15 onward not started. |
| Automated tests | `npm run check` (unit, contracts, registry), `test:database` (native PostgreSQL 17.11) and `test:database:wasm`, `test:server` (API against native PostgreSQL with a non-superuser login), `test:web` (production Next.js server). All pass on `main` in GitHub Actions (`foundation`, `database`). |
| Security review | AI-assisted review and adversarial tests per owner policy (AGENTS.md). Independent human review / penetration test: **pending, deferred** (not a blocker). No certification claimed. |
| Deployment | Render service `heard-web` at https://heard-web-ug5f.onrender.com (free plan, auto-deploy from `main`, Neon PostgreSQL 16), set up by the lead; intake disabled. See [DEPLOYMENT_RENDER.md](DEPLOYMENT_RENDER.md). |
| Sensitive intake | **Disabled by default** (`HEARD_INTAKE_ENABLED=false`). Do not enable for real contributors before the §16 release gates. |

## Merged work units

| Unit | PR | Summary | Design / limits |
|---|---|---|---|
| HEARD-01 | #7 | Product charter, requirements ledger | PRODUCT_REQUIREMENTS.md |
| HEARD-02 | #8 | Threat model, data map, privacy architecture | THREAT_MODEL.md |
| HEARD-03 | #22 (draft #9 superseded) | npm workspaces, strict TS, Biome, secretlint, history scan, CI, artifact | WORKSPACE_PLAN.md |
| HEARD-04 | #23 (draft #10) | Checksum-bound migrator, default-deny RLS, scoped roles, fixtures | SCHEMA_MIGRATION_NOTES.md |
| HEARD-05 | #25 (stub #11) | Secure Intake adapter: local PostgreSQL implementation; remote fail-closed | SECURE_INTAKE_ADAPTER.md |
| HEARD-06 | #24 (stub #12) | Config schema, liveness/readiness, redacted logs, env binding, Node web service, render.yaml | DEPLOYMENT_RENDER.md |
| HEARD-07 | #26 (stub #13) | Anonymous principals, one-time recovery codes, sessions, pseudonyms, staff MFA assurance | IDENTITY.md |
| HEARD-08 | #27 (stub #14) | Policy-as-code + RLS, assignments, grants, audited denials | AUTHORIZATION.md |
| HEARD-09 | #28 (stub #15) | Versioned, digest-bound, append-only consent; preview | CONSENT.md |
| HEARD-10/11 | #29 (stubs #16, #17) | Accessible wizard; encrypted drafts; idempotent receipts | INTAKE.md |
| HEARD-12 | #30 (stub #18) | Resumable private uploads; storage adapters (memory/fs/S3-B2) | UPLOADS.md |
| HEARD-13 | #31 (stub #19) | Quarantine, type/content checks, clamd scanning, cleared-only delivery, worker | QUARANTINE.md |
| HEARD-14 | #33 | Immutable originals, DB-computed hash-chained handling ledger, byte verification, source statements, private manifest | EVIDENCE_LEDGER.md |

Database migrations on `main`: `0001`–`0011` (checksum-bound; never edit applied files).

## Known blockers and gaps

- **Secure Intake engine (remote):** upstream API/version/signing contract not verified against a deployed engine; the local adapter is used. See SECURE_INTAKE_ADAPTER.md.
- **External services not provisioned:** Neon database, B2 bucket, ClamAV, email provider, signing keys. Every one sits behind an interface with a fake/local adapter and documented variables.
- **Identity:** named accounts with passkeys and an HTTP staff MFA ceremony are not implemented; staff provisioning is operator-script only.
- **Accessibility:** wizard follows WCAG patterns but has not had browser/assistive-technology or axe testing (HEARD-44).
- **Rate limiting** is per process; multi-instance deployment needs a shared limiter.
- `security/e2eesa-*.json` and `.github/deployment-monitor.json` still name `neophilism/HEARD` because their validators/consumers (E2EESA status contract, Development Deployment Monitor) are separate cross-repository contracts; update them together with those consumers.
- Branches `boardroom/HEARD-05` … `boardroom/HEARD-13` and `agent/heard-03-complete` are superseded (their PRs are closed); they can be deleted by the owner.

## How to continue

```sh
npm ci --ignore-scripts
npm run check && npm run check:types && npm run lint
npm run test:database && npm run test:database:wasm && npm run test:server
npm run build && npm run test:web
```

Next dependency-ready units: **HEARD-15** (durable job framework; generalize the scan-job leasing in `packages/quarantine` into a shared leased queue with dead-lettering and cancellation), then HEARD-16…19 media processing, HEARD-20/21 case workflow and reviewer console. Keep new RLS policies on the reviewed allowlist in `db/tests/no-permissive-policies.sql`, keep publications default-deny until HEARD-23, and map every merged PR in `registry/prs.json` (`npm run check:registry`).

## Discipline

Never commit secrets or real personal data (fictional fixtures only). Keep implementation, testing, external review, certification and deployment as distinct statuses. Update this file and the registry at every merged milestone.
