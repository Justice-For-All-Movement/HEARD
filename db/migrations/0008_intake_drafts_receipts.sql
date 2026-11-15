-- HEARD-10/11: encrypted intake drafts with optimistic revisions, idempotent
-- submission receipts and an expiry purge path for the job worker.
BEGIN;
CREATE TABLE IF NOT EXISTS heard_intake_drafts (
 case_id uuid PRIMARY KEY REFERENCES heard_cases(id),
 schema_version text NOT NULL CHECK(char_length(schema_version) BETWEEN 1 AND 40),
 revision integer NOT NULL DEFAULT 0 CHECK(revision >= 0),
 ciphertext text NOT NULL CHECK(char_length(ciphertext) BETWEEN 1 AND 200000 AND ciphertext ~ '^v1\.[A-Za-z0-9_-]{1,32}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
 updated_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_heard_drafts_expiry ON heard_intake_drafts(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS heard_submission_receipts (
 case_id uuid PRIMARY KEY REFERENCES heard_cases(id),
 reference text NOT NULL UNIQUE CHECK(reference ~ '^HRD-R-[0-9A-HJKMNP-TV-Z]{10}$'),
 idempotency_key_hash text NOT NULL CHECK(idempotency_key_hash ~ '^[a-f0-9]{64}$'),
 schema_version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE heard_intake_drafts ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_intake_drafts FORCE ROW LEVEL SECURITY;
ALTER TABLE heard_submission_receipts ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_submission_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON heard_intake_drafts, heard_submission_receipts FROM PUBLIC;

GRANT SELECT, INSERT, DELETE ON heard_intake_drafts TO heard_api;
GRANT UPDATE (schema_version, revision, ciphertext, key_id, updated_at, expires_at) ON heard_intake_drafts TO heard_api;
GRANT SELECT, INSERT ON heard_submission_receipts TO heard_api;
GRANT SELECT, DELETE ON heard_intake_drafts TO heard_job_worker;
GRANT SELECT ON heard_cases TO heard_job_worker;
GRANT UPDATE (status, updated_at) ON heard_cases TO heard_job_worker;
GRANT EXECUTE ON FUNCTION heard_assigned(uuid) TO heard_job_worker;

-- Drafts: owners read theirs; write only while the case is still a draft; assigned MFA staff read submitted answers.
DROP POLICY IF EXISTS heard_drafts_owner_read ON heard_intake_drafts;
CREATE POLICY heard_drafts_owner_read ON heard_intake_drafts FOR SELECT TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR (heard_assigned(c.id) AND c.status <> 'draft'))));
DROP POLICY IF EXISTS heard_drafts_owner_create ON heard_intake_drafts;
CREATE POLICY heard_drafts_owner_create ON heard_intake_drafts FOR INSERT TO heard_api
 WITH CHECK (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject() AND c.status = 'draft'));
DROP POLICY IF EXISTS heard_drafts_owner_update ON heard_intake_drafts;
CREATE POLICY heard_drafts_owner_update ON heard_intake_drafts FOR UPDATE TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject() AND c.status = 'draft'))
 WITH CHECK (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));
DROP POLICY IF EXISTS heard_drafts_owner_delete ON heard_intake_drafts;
CREATE POLICY heard_drafts_owner_delete ON heard_intake_drafts FOR DELETE TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));

-- Receipts: owner only.
DROP POLICY IF EXISTS heard_receipts_owner_read ON heard_submission_receipts;
CREATE POLICY heard_receipts_owner_read ON heard_submission_receipts FOR SELECT TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));
DROP POLICY IF EXISTS heard_receipts_owner_create ON heard_submission_receipts;
CREATE POLICY heard_receipts_owner_create ON heard_submission_receipts FOR INSERT TO heard_api
 WITH CHECK (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject() AND c.status = 'submitted'));

-- Expiry purge (job worker, declared purpose): only expired, unsubmitted drafts.
DROP POLICY IF EXISTS heard_drafts_expiry_purge ON heard_intake_drafts;
CREATE POLICY heard_drafts_expiry_purge ON heard_intake_drafts FOR ALL TO heard_job_worker
 USING (heard_setting('job_purpose') = 'draft_expiry' AND expires_at IS NOT NULL AND expires_at < now());
-- The job sees only cases that still have an expired draft (the draft row is deleted
-- after withdrawal in the same transaction), and may only move them draft -> withdrawn.
CREATE OR REPLACE FUNCTION heard_draft_expired(target_case uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT heard_setting('job_purpose') = 'draft_expiry' AND EXISTS (
  SELECT 1 FROM heard_intake_drafts d WHERE d.case_id = target_case AND d.expires_at IS NOT NULL AND d.expires_at < now())
$$;
REVOKE ALL ON FUNCTION heard_draft_expired(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION heard_draft_expired(uuid) TO heard_job_worker;
DROP POLICY IF EXISTS heard_cases_expiry_read ON heard_cases;
CREATE POLICY heard_cases_expiry_read ON heard_cases FOR SELECT TO heard_job_worker
 USING (heard_draft_expired(id));
DROP POLICY IF EXISTS heard_cases_expiry_withdraw ON heard_cases;
CREATE POLICY heard_cases_expiry_withdraw ON heard_cases FOR UPDATE TO heard_job_worker
 USING (status = 'draft' AND heard_draft_expired(id))
 WITH CHECK (status = 'withdrawn' AND heard_draft_expired(id));
COMMIT;
