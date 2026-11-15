-- HEARD-15: general durable job framework on heard_jobs. Workers are scoped per job
-- kind (heard.job_purpose = kind); contributors can see and cancel jobs on their cases.
BEGIN;
ALTER TABLE heard_jobs ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(payload) = 'object' AND pg_column_size(payload) < 2048);
ALTER TABLE heard_jobs ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;
ALTER TABLE heard_jobs ADD CONSTRAINT heard_jobs_kind_format CHECK(kind ~ '^[a-z][a-z0-9_]{1,63}$') NOT VALID;
ALTER TABLE heard_jobs ADD CONSTRAINT heard_jobs_cancel_consistent CHECK((state = 'cancelled') = (cancelled_at IS NOT NULL)) NOT VALID;
CREATE INDEX IF NOT EXISTS idx_heard_jobs_case ON heard_jobs(case_id, created_at);

GRANT SELECT ON heard_jobs TO heard_api;
GRANT UPDATE (state, cancelled_at, finished_at, lease_owner, lease_until) ON heard_jobs TO heard_api;
GRANT UPDATE (payload) ON heard_jobs TO heard_job_worker;

-- Workers see and update only jobs of the kind they declared.
DROP POLICY IF EXISTS heard_jobs_scan_worker ON heard_jobs;
DROP POLICY IF EXISTS heard_jobs_worker ON heard_jobs;
CREATE POLICY heard_jobs_worker ON heard_jobs FOR ALL TO heard_job_worker
 USING (kind = heard_setting('job_purpose'))
 WITH CHECK (kind = heard_setting('job_purpose'));

-- Contributors see job status on their own cases and may cancel jobs that have not finished.
DROP POLICY IF EXISTS heard_jobs_owner_read ON heard_jobs;
CREATE POLICY heard_jobs_owner_read ON heard_jobs FOR SELECT TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));
DROP POLICY IF EXISTS heard_jobs_owner_cancel ON heard_jobs;
CREATE POLICY heard_jobs_owner_cancel ON heard_jobs FOR UPDATE TO heard_api
 USING (state IN ('queued','leased') AND EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()))
 WITH CHECK (state = 'cancelled' AND lease_owner IS NULL AND EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));
COMMIT;
