# Malware quarantine and parser safety (HEARD-13)

Every completed upload (HEARD-12) is recorded as `quarantined` and a scan job is enqueued in the same transaction. The only way an object becomes readable is the scan worker (`npm run worker`, `packages/quarantine`) setting it to `cleared`, and a database constraint additionally requires a `clean` verdict from a named engine, a scan time and a detected type equal to the declared type.

## What the worker checks, in order

1. **Integrity** — re-reads the stored bytes and compares size and SHA-256 with the upload record (`integrity_mismatch`).
2. **Real type** — magic-byte detection (JPEG, PNG, PDF, MP4/QuickTime/M4A `ftyp` brands, MP3); unknown or different from the declaration → `type_mismatch`. Names/extensions are never consulted (none are stored).
3. **Content safety without parsing** — PDFs containing `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile(s)`, `/RichMedia`, `/XFA`, `/AA`, `/SubmitForm`, `/ImportData` → `pdf_active_content`; non-PDF files with HTML/SVG/script, ZIP or PDF markers in their first MiB → `polyglot_marker`. Markers split across chunk boundaries are caught.
4. **Malware scan** — ClamAV `clamd` over TCP (INSTREAM, 120 s deadline) or, in local/ci only, a fake scanner that flags the EICAR test string. `infected` → `malware`.

Scanner absence (`HEARD_SCANNER_DRIVER=none`), errors, size-limit replies and timeouts are **not verdicts**: the object stays quarantined (`scan_pending`), the job retries with backoff (30 s, 2 min, 10 min) and after 4 attempts closes as `failed` with the object left `quarantined` / `scan_failed`. Rejected bytes stay in the private quarantine prefix and are never served; deletion follows the retention policy (HEARD-41).

Jobs are leased with `FOR UPDATE SKIP LOCKED`, completion is compare-and-set on the lease owner, and expired leases are recovered by other workers, so several workers can run safely. The worker runs as `heard_job_worker` with a declared purpose; RLS limits it to scan jobs and the objects they reference.

## Delivery

`GET /api/v1/objects/{id}` serves only `cleared` objects to the owner, assigned MFA staff or an explicit active grant recipient, as `attachment` with the detected type, `nosniff`, `CSP: sandbox`, `no-store` and same-origin resource policy. `GET /api/v1/my/cases/{id}/objects` lists states without storage keys.

## Limits

- No decompression of PDF object streams or content disarm and reconstruction (CDR); ClamAV's own PDF heuristics apply when clamd is configured. Media are not transcoded here (HEARD-16).
- Worker isolation (separate container without public ingress, resource caps, egress limited to database/storage/clamd) is a deployment property for HEARD-46; ClamAV signature freshness must be monitored.
