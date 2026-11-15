# Identity, sessions and anonymous recovery (HEARD-07)

Implemented in `packages/identity`, `packages/server/src/identity-routes.mjs` and migration `0005_identity_sessions_recovery.sql`. All routes are absent (404) unless `HEARD_INTAKE_ENABLED=true`.

## Principals and credentials

| Concept | Storage | Notes |
|---|---|---|
| Anonymous principal | `heard_subjects(kind='anonymous')` | Random UUID. No email, phone or name is requested. |
| Recovery code | `heard_recovery_credentials.verifier` = HMAC-SHA256(`HEARD_SESSION_SECRET`, code) | 125-bit Crockford base32 (`HRD-XXXXX-…`), shown once. **One-time**: redeeming consumes it atomically and issues a new code. One active code per principal. |
| Session | `heard_sessions.token_hash` = HMAC of a 256-bit token | `__Host-` cookie, `HttpOnly; Secure; SameSite=Strict`. 12 h absolute, 2 h idle; staff 8 h. Revocable; locked principals lose access immediately. |
| Public alias | `heard_profiles` | Optional pseudonym, NFKC-normalized, confusable/mixed-script/reserved-word checks, unique by skeleton key. Separate from any legal identity. |
| Staff membership | `heard_staff_memberships` | Provisioned only through the `heard_operator` role with a declared purpose; expiry required; staff sessions require MFA assurance (`staff_mfa`). Membership alone grants no case access (HEARD-08). |

## API (`/api/v1`)

`POST anonymous/start`, `POST anonymous/redeem {recoveryCode}`, `GET session`, `DELETE session`, `POST recovery/rotate`, `PUT profile {alias, language}`. Mutations require JSON, an `Origin` equal to `HEARD_PUBLIC_ORIGIN` and no cross-site fetch metadata. Unknown, used and revoked recovery codes return the same `401 INVALID_RECOVERY_CODE`. Start and redeem are rate-limited per client (HMAC'd right-most `X-Forwarded-For`; raw IPs are not stored).

## Database enforcement

The application connects as a non-superuser login that can `SET LOCAL ROLE heard_api` per transaction with `heard.subject_id` set. Forced RLS policies expose only the subject's own rows, or the single session/recovery row whose verifier the caller presented. Column-level grants make ownership columns immutable to the API role; the API role cannot create sessions for other subjects, self-grant staff roles or write audit events attributed to anyone else. `db/tests/no-permissive-policies.sql` rejects unreviewed, PUBLIC or unconditional policies.

## Limits (honest)

- A pseudonym or anonymous session does not hide IP addresses, timing, writing style or media metadata from hosting, database and network providers; the API returns this notice on start.
- Losing the recovery code means losing access to an anonymous principal; support staff cannot recover it (by design, to resist impersonation).
- Named accounts with passkeys and the staff MFA ceremony (WebAuthn/TOTP) are not implemented yet; `startStaffSession` requires the caller to have verified MFA and is not exposed over HTTP.
- The rate limiter is per process; multi-instance deployments need a shared limiter.
