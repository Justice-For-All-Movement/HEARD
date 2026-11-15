# Deny-by-default resource authorization (HEARD-08)

Implemented in `packages/authorization` and migration `0006_resource_authorization.sql`. Two independent layers must both allow an access:

1. **Policy-as-code** (`decide`): a pure function of a server-resolved principal (from a verified session: subject, assurance level, active staff roles), an action from a closed list, a resource loaded inside the principal's own RLS scope, and server-side facts (assignments, grants, approvals). Unlisted actions and missing facts deny.
2. **PostgreSQL forced RLS**: rows outside the principal's reach are invisible or unwritable even if application code is wrong.

| Principal | Allowed | Never |
|---|---|---|
| Case owner | read own cases; edit/submit drafts; withdraw; record consent; upload to drafts; read own evidence; create/revoke single-object grants | move own case into review/closed; change ownership, kind or visibility; grant to self |
| Helper (grant recipient) | `evidence.read` on the exact granted object while unexpired and unrevoked | the case record, other objects, altering the grant |
| Reviewer / editor / safety staff | `review.*` / `publication.review` only with an MFA (`staff_mfa`) session **and** a live assignment to that case in a matching role; never drafts | their own cases (DB trigger rejects self-assignment); any case without assignment |
| Administrator role | nothing by itself | case or evidence access without an assignment; identity reveal |
| Identity reveal (C3) | safety staff with MFA plus two distinct safety approvals excluding requester and owner | single-person reveal |

Unknown and forbidden resources both return `NOT_FOUND`. Sensitive allowed actions and **all denials** are written to the append-only audit log; denials are committed in a separate transaction after the denied work rolls back, and record the target ID in metadata rather than as a foreign key (no existence oracle). A database trigger enforces the case state machine (`draft→submitted→review→closed`, withdrawal from any non-terminal state) and immutability of owner/kind/visibility. Staff assignments are created only through the purpose-declaring `heard_operator` role.

Adversarial coverage: `tests/authorization.test.mjs` (decision matrix) and `tests/server/authorization.test.mjs` (horizontal/vertical IDOR, guessed IDs, blind updates, forged grantor, revocation, expiry, MFA, administrator, self-review, audit) on native PostgreSQL with a non-superuser application login.
