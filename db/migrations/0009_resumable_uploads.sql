-- HEARD-12: bounded, resumable, owner-scoped upload sessions into private quarantine storage.
BEGIN;
CREATE TABLE IF NOT EXISTS heard_upload_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 case_id uuid NOT NULL REFERENCES heard_cases(id),
 subject_id uuid NOT NULL REFERENCES heard_subjects(id),
 declared_type text NOT NULL CHECK(declared_type IN ('image/jpeg','image/png','application/pdf','video/mp4','video/quicktime','audio/mpeg','audio/mp4')),
 declared_size bigint NOT NULL CHECK(declared_size > 0 AND declared_size <= 314572800),
 expected_sha256 text NOT NULL CHECK(expected_sha256 ~ '^[a-f0-9]{64}$'),
 chunk_size integer NOT NULL CHECK(chunk_size BETWEEN 65536 AND 16777216),
 part_count integer NOT NULL CHECK(part_count BETWEEN 1 AND 10000),
 storage_key text NOT NULL UNIQUE CHECK(storage_key ~ '^quarantine/[0-9a-f-]{36}$'),
 storage_upload_id text NOT NULL CHECK(char_length(storage_upload_id) BETWEEN 1 AND 1024),
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','completing','completed','aborted','rejected','expired')),
 object_id uuid REFERENCES heard_private_objects(id),
 rejection text CHECK(rejection IS NULL OR rejection ~ '^[a-z_]{1,40}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 completed_at timestamptz,
 CHECK(expires_at > created_at),
 CHECK((state = 'completed') = (object_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_heard_upload_sessions_case ON heard_upload_sessions(case_id);
CREATE INDEX IF NOT EXISTS idx_heard_upload_sessions_open ON heard_upload_sessions(expires_at) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS heard_upload_parts (
 session_id uuid NOT NULL REFERENCES heard_upload_sessions(id),
 part_number integer NOT NULL CHECK(part_number BETWEEN 1 AND 10000),
 size integer NOT NULL CHECK(size > 0),
 sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
 etag text NOT NULL CHECK(char_length(etag) BETWEEN 1 AND 200),
 uploaded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(session_id, part_number)
);

ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS declared_type text;
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS size_bytes bigint CHECK(size_bytes IS NULL OR size_bytes > 0);
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS upload_session_id uuid UNIQUE;

ALTER TABLE heard_upload_sessions ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_upload_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE heard_upload_parts ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_upload_parts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON heard_upload_sessions, heard_upload_parts FROM PUBLIC;
GRANT SELECT, INSERT ON heard_upload_sessions, heard_upload_parts TO heard_api;
GRANT UPDATE (state, object_id, rejection, completed_at) ON heard_upload_sessions TO heard_api;
GRANT UPDATE (size, sha256, etag, uploaded_at) ON heard_upload_parts TO heard_api;
GRANT SELECT ON heard_upload_sessions TO heard_job_worker;
GRANT UPDATE (state) ON heard_upload_sessions TO heard_job_worker;

-- Sessions belong to the uploading owner of a case.
DROP POLICY IF EXISTS heard_uploads_owner_read ON heard_upload_sessions;
CREATE POLICY heard_uploads_owner_read ON heard_upload_sessions FOR SELECT TO heard_api
 USING (subject_id = heard_current_subject());
DROP POLICY IF EXISTS heard_uploads_owner_create ON heard_upload_sessions;
CREATE POLICY heard_uploads_owner_create ON heard_upload_sessions FOR INSERT TO heard_api
 WITH CHECK (subject_id = heard_current_subject() AND state = 'open' AND EXISTS (
  SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject() AND c.status = 'draft'));
DROP POLICY IF EXISTS heard_uploads_owner_update ON heard_upload_sessions;
CREATE POLICY heard_uploads_owner_update ON heard_upload_sessions FOR UPDATE TO heard_api
 USING (subject_id = heard_current_subject()) WITH CHECK (subject_id = heard_current_subject());

DROP POLICY IF EXISTS heard_upload_parts_owner ON heard_upload_parts;
CREATE POLICY heard_upload_parts_owner ON heard_upload_parts FOR ALL TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_upload_sessions s WHERE s.id = session_id AND s.subject_id = heard_current_subject()))
 WITH CHECK (EXISTS (SELECT 1 FROM heard_upload_sessions s WHERE s.id = session_id AND s.subject_id = heard_current_subject() AND s.state = 'open'));

-- Expiry job: only open sessions past their expiry, only to 'expired'.
DROP POLICY IF EXISTS heard_uploads_expiry_read ON heard_upload_sessions;
CREATE POLICY heard_uploads_expiry_read ON heard_upload_sessions FOR SELECT TO heard_job_worker
 USING (heard_setting('job_purpose') = 'upload_expiry' AND expires_at < now());
DROP POLICY IF EXISTS heard_uploads_expiry_update ON heard_upload_sessions;
CREATE POLICY heard_uploads_expiry_update ON heard_upload_sessions FOR UPDATE TO heard_job_worker
 USING (heard_setting('job_purpose') = 'upload_expiry' AND expires_at < now() AND state = 'open')
 WITH CHECK (heard_setting('job_purpose') = 'upload_expiry' AND state = 'expired');
COMMIT;
