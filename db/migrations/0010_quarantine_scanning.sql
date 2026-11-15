-- HEARD-13: content verification and malware scanning. An object can only become
-- 'cleared' with a clean verdict from a named engine and a detected type equal to
-- the declared type; nothing else can promote it.
BEGIN;
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS detected_type text;
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS scan_verdict text CHECK(scan_verdict IS NULL OR scan_verdict IN ('clean','infected','unavailable','error'));
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS scan_engine text CHECK(scan_engine IS NULL OR scan_engine ~ '^[A-Za-z0-9_./ -]{1,80}$');
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS scanned_at timestamptz;
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS quarantine_reason text CHECK(quarantine_reason IS NULL OR quarantine_reason ~ '^[a-z_]{1,40}$');
ALTER TABLE heard_private_objects ADD CONSTRAINT heard_objects_cleared_requires_scan CHECK(
 quarantine_state <> 'cleared' OR (scan_verdict = 'clean' AND scan_engine IS NOT NULL AND scanned_at IS NOT NULL AND detected_type IS NOT NULL AND detected_type = declared_type)) NOT VALID;

ALTER TABLE heard_jobs ADD COLUMN IF NOT EXISTS object_id uuid REFERENCES heard_private_objects(id);
ALTER TABLE heard_jobs ADD COLUMN IF NOT EXISTS available_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE heard_jobs ADD COLUMN IF NOT EXISTS last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$');
ALTER TABLE heard_jobs ADD COLUMN IF NOT EXISTS finished_at timestamptz;
ALTER TABLE heard_jobs ADD CONSTRAINT heard_jobs_scan_has_object CHECK(kind <> 'scan' OR object_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_heard_jobs_ready ON heard_jobs(kind, available_at) WHERE state IN ('queued','leased');

GRANT INSERT ON heard_jobs TO heard_api;
GRANT SELECT ON heard_private_objects TO heard_job_worker;
GRANT UPDATE (quarantine_state, detected_type, scan_verdict, scan_engine, scanned_at, quarantine_reason) ON heard_private_objects TO heard_job_worker;
GRANT UPDATE (state, attempts, lease_owner, lease_until, available_at, last_error_code, finished_at) ON heard_jobs TO heard_job_worker;

-- Contributors enqueue exactly a queued scan of an object in their own case.
DROP POLICY IF EXISTS heard_jobs_enqueue_scan ON heard_jobs;
CREATE POLICY heard_jobs_enqueue_scan ON heard_jobs FOR INSERT TO heard_api
 WITH CHECK (kind = 'scan' AND state = 'queued' AND attempts = 0 AND lease_owner IS NULL AND EXISTS (
  SELECT 1 FROM heard_private_objects o JOIN heard_cases c ON c.id = o.case_id
  WHERE o.id = object_id AND o.case_id = heard_jobs.case_id AND c.subject_id = heard_current_subject() AND o.quarantine_state = 'quarantined'));

-- The scan worker (declared purpose) sees and updates scan jobs only.
DROP POLICY IF EXISTS heard_jobs_scan_worker ON heard_jobs;
CREATE POLICY heard_jobs_scan_worker ON heard_jobs FOR ALL TO heard_job_worker
 USING (heard_setting('job_purpose') = 'scan' AND kind = 'scan')
 WITH CHECK (heard_setting('job_purpose') = 'scan' AND kind = 'scan');

-- ...and only the objects those jobs reference.
CREATE OR REPLACE FUNCTION heard_scan_target(target uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT heard_setting('job_purpose') = 'scan' AND EXISTS (
  SELECT 1 FROM heard_jobs j WHERE j.object_id = target AND j.kind = 'scan' AND j.state IN ('queued','leased'))
$$;
REVOKE ALL ON FUNCTION heard_scan_target(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION heard_scan_target(uuid) TO heard_job_worker;
DROP POLICY IF EXISTS heard_objects_scan_read ON heard_private_objects;
CREATE POLICY heard_objects_scan_read ON heard_private_objects FOR SELECT TO heard_job_worker
 USING (heard_scan_target(id));
DROP POLICY IF EXISTS heard_objects_scan_update ON heard_private_objects;
CREATE POLICY heard_objects_scan_update ON heard_private_objects FOR UPDATE TO heard_job_worker
 USING (heard_scan_target(id) AND quarantine_state = 'quarantined')
 WITH CHECK (heard_scan_target(id) AND quarantine_state IN ('quarantined','cleared','rejected'));
COMMIT;
