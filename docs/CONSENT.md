# Privacy choices and versioned consent (HEARD-09)

Implemented in `packages/consent`, `packages/server/src/consent-routes.mjs` and migration `0007_versioned_consent.sql`.

## Purposes (independent)

| Purpose | Required scope | Depends on | Used by |
|---|---|---|---|
| `private_processing` | — | — | submitting a draft (HEARD-11) |
| `contact` | `channels` (`in_app` only for now) | — | notifications (HEARD-34) |
| `helper_access` | `recipients`, `assets` (UUIDs) | — | helper grants (HEARD-30/31) |
| `publication` | `assets`, `fields` | `identity_display` | publication projector (HEARD-23) |
| `identity_display` | `mode`: named / pseudonymous / private | — | public attribution |
| `archive_replication` | — | `publication` | Liberty Nodes export (HEARD-38) |

No purpose inherits from another; dependencies only *restrict* (publication without an identity-display choice, or replication without publication, is not in effect).

## Rules

- Every decision is an append-only row (`UPDATE`/`DELETE` rejected by trigger) ordered by a database sequence, so the latest event wins without clock ties.
- A grant is bound to the policy **version and SHA-256 of the exact text**. The client must echo the displayed version; otherwise `409`. Changing a policy's text creates a new digest, so earlier grants become `stale` and stop working until the contributor decides again.
- Grants may expire; revocation takes effect immediately for future actions. Text for helper access, publication and replication states that copies already made cannot be recalled.
- Scope matching is exact: a new asset, recipient or field is not covered by an earlier grant.
- `disclosurePreview` is derived from the same function (`consentCovers`) that enforces consent, so the plain-language preview cannot drift from effective permissions.
- RLS: only the case owner can record consent; owners and assigned MFA staff can read it. Grants without a text digest are rejected by a constraint.

## API

`GET /api/v1/consent/policies` (texts, versions, digests), `GET /api/v1/my/cases/{id}/consents` (effective state + preview), `POST /api/v1/my/cases/{id}/consents {purpose, decision, policyVersion, scope?, expiresAt?}`. All behind the intake flag; non-owners get `404`.

Policy texts are engineering drafts and require editorial/legal review before launch (DEVELOPMENT_PLAN §0.5).
