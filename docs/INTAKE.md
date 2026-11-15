# Intake wizard, drafts and receipts (HEARD-10, HEARD-11)

Disabled by default. With `HEARD_INTAKE_ENABLED=true` (plus database and keys), `/share` links to `/share/start`; otherwise `/share/start` and every intake API return 404 and no form is rendered anywhere.

## Wizard (HEARD-10)

One versioned schema (`packages/intake`, `INTAKE_SCHEMA_VERSION`) drives the UI, server validation and classification. Steps: pathway → privacy choices → in your own words → when and where → what would help → supporting material (uploads not yet available) → review.

- Every field has a classification (C1 metadata, C2 narrative, C3 identifying), a label, limits and options. No legal name, email, phone or address is ever requested; C3 fields are always optional and their precision is the contributor's choice (year/month/day; country/region/city), enforced server-side. Street addresses are refused.
- Unknown fields are rejected, so nothing unclassified is stored. Only `kind`, the identity-display choice and the narrative are required.
- Accessibility (implemented, not yet externally audited): one `h1` per page; each step is a form with labelled inputs, `fieldset`/`legend` for choices, hints and errors linked by `aria-describedby`, `aria-invalid`, an error summary that receives focus and links to fields, focus moved to each step heading, a polite live progress indicator and character count, 44 px targets, visible focus outlines, no time limits. Canonical copy from `content/site-copy.json` is used for actions and notices.
- The privacy step shows the full `private_processing` policy text and requires explicit agreement before continuing; the identity choice explains that a pseudonym may not prevent recognition.

## Drafts, recovery and receipts (HEARD-11)

- `POST /api/v1/drafts {kind}` creates a private case (via the Secure Intake adapter) and an encrypted draft; at most 5 open drafts per principal; drafts expire after 30 days of inactivity.
- Answers are encrypted with AES-256-GCM using `HEARD_DATA_ENCRYPTION_KEY`; the case ID, schema version and key ID are authenticated data, so a ciphertext cannot be moved between cases or relabelled. Key IDs support a read key ring for rotation.
- `PUT /api/v1/drafts/{id} {revision, answers}` saves only if `revision` is current (`409` otherwise): conflicting tabs cannot silently erase content. Kind is fixed at creation.
- `POST /api/v1/drafts/{id}/submit {revision}` with an `Idempotency-Key` header: requires the reviewed revision, complete valid answers and current processing consent, then transitions the case, stops draft expiry and issues a random receipt reference (`HRD-R-…`) in one transaction. Retries with the same key return the same receipt (`200`); concurrent retries produce exactly one submission; other attempts get `409`.
- `DELETE /api/v1/drafts/{id}` withdraws; for an unsubmitted draft the encrypted answers are deleted immediately.
- `GET /api/v1/my/cases` and `/api/v1/my/cases/{id}` show status and receipt reference only. The reference is not a credential; access needs a session (anonymous contributors resume with their one-time recovery code).
- `purgeExpiredDrafts` runs as `heard_job_worker` with a declared purpose; RLS limits it to cases that still have an expired draft and to the draft→withdrawn transition. (Scheduling it as a Render cron job is HEARD-15/46 work.)
- RLS: owners read/write their drafts only while in draft; assigned MFA staff can read submitted answers; nobody else sees drafts or receipts.

## Not yet

Browser-based assistive-technology and automated axe testing (HEARD-44), uploads (HEARD-12/13), contributor follow-up inbox (HEARD-22), retention of submitted answers (HEARD-41).
