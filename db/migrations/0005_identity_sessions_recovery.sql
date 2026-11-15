-- HEARD-07: anonymous principals, pseudonymous profiles, server-side sessions,
-- one-time recovery credentials and staff memberships, with RLS policies scoped to
-- the authenticated subject (transaction-local setting heard.subject_id).
BEGIN;

CREATE OR REPLACE FUNCTION heard_current_subject() RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE AS
$$ SELECT nullif(current_setting('heard.subject_id', true), '')::uuid $$;
CREATE OR REPLACE FUNCTION heard_setting(setting_name text) RETURNS text LANGUAGE sql STABLE PARALLEL SAFE AS
$$ SELECT nullif(current_setting('heard.' || setting_name, true), '') $$;
REVOKE ALL ON FUNCTION heard_current_subject(), heard_setting(text) FROM PUBLIC;

DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='heard_operator') THEN
  CREATE ROLE heard_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
 END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='heard_operator' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolcanlogin OR rolreplication OR rolinherit)) THEN
  RAISE EXCEPTION 'Unsafe preexisting role attributes for heard_operator';
 END IF;
END $$;
GRANT USAGE ON SCHEMA public TO heard_operator;
GRANT EXECUTE ON FUNCTION heard_current_subject(), heard_setting(text) TO heard_api, heard_job_worker, heard_public_projector, heard_operator;
GRANT heard_operator TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

ALTER TABLE heard_subjects ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'anonymous' CHECK(kind IN ('anonymous','account','staff'));

CREATE TABLE IF NOT EXISTS heard_profiles (
 subject_id uuid PRIMARY KEY REFERENCES heard_subjects(id),
 public_alias text CHECK(public_alias IS NULL OR char_length(public_alias) BETWEEN 3 AND 48),
 alias_key text UNIQUE CHECK(alias_key IS NULL OR char_length(alias_key) BETWEEN 3 AND 48),
 language text NOT NULL DEFAULT 'en' CHECK(language ~ '^[a-z]{2,3}(-[A-Z]{2})?$'),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK((public_alias IS NULL) = (alias_key IS NULL))
);

CREATE TABLE IF NOT EXISTS heard_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 subject_id uuid NOT NULL REFERENCES heard_subjects(id),
 token_hash text NOT NULL UNIQUE CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 assurance text NOT NULL CHECK(assurance IN ('anonymous_recovery','account','staff_mfa')),
 created_at timestamptz NOT NULL DEFAULT now(),
 last_seen_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK(expires_at > created_at),
 CHECK(revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX IF NOT EXISTS idx_heard_sessions_subject ON heard_sessions(subject_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS heard_recovery_credentials (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 subject_id uuid NOT NULL REFERENCES heard_subjects(id),
 verifier text NOT NULL UNIQUE CHECK(verifier ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 used_at timestamptz,
 revoked_at timestamptz,
 CHECK(used_at IS NULL OR used_at >= created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_heard_recovery_one_active ON heard_recovery_credentials(subject_id) WHERE revoked_at IS NULL AND used_at IS NULL;

CREATE TABLE IF NOT EXISTS heard_staff_memberships (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 subject_id uuid NOT NULL REFERENCES heard_subjects(id),
 role text NOT NULL CHECK(role IN ('reviewer','editor','safety','administrator')),
 purpose text NOT NULL CHECK(char_length(trim(purpose)) BETWEEN 3 AND 200),
 granted_by uuid REFERENCES heard_subjects(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK(expires_at > created_at),
 CHECK(granted_by IS NULL OR granted_by <> subject_id)
);

ALTER TABLE heard_profiles ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE heard_sessions ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE heard_recovery_credentials ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_recovery_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE heard_staff_memberships ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_staff_memberships FORCE ROW LEVEL SECURITY;
REVOKE ALL ON heard_profiles, heard_sessions, heard_recovery_credentials, heard_staff_memberships FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE ON heard_profiles TO heard_api;
GRANT SELECT, INSERT ON heard_subjects, heard_sessions, heard_recovery_credentials TO heard_api;
-- Column-level UPDATE: ownership columns can never be rewritten by the API role.
GRANT UPDATE (account_state) ON heard_subjects TO heard_api;
GRANT UPDATE (last_seen_at, revoked_at) ON heard_sessions TO heard_api;
GRANT UPDATE (used_at, revoked_at) ON heard_recovery_credentials TO heard_api;
GRANT SELECT ON heard_staff_memberships TO heard_api;
GRANT SELECT, INSERT, UPDATE ON heard_subjects, heard_staff_memberships TO heard_operator;

-- Subjects: a principal sees and creates only itself.
DROP POLICY IF EXISTS heard_subjects_self ON heard_subjects;
CREATE POLICY heard_subjects_self ON heard_subjects FOR ALL TO heard_api
 USING (id = heard_current_subject()) WITH CHECK (id = heard_current_subject());
DROP POLICY IF EXISTS heard_subjects_operator ON heard_subjects;
CREATE POLICY heard_subjects_operator ON heard_subjects FOR ALL TO heard_operator
 USING (heard_setting('operator_purpose') IS NOT NULL) WITH CHECK (heard_setting('operator_purpose') IS NOT NULL AND kind = 'staff');

DROP POLICY IF EXISTS heard_profiles_self ON heard_profiles;
CREATE POLICY heard_profiles_self ON heard_profiles FOR ALL TO heard_api
 USING (subject_id = heard_current_subject()) WITH CHECK (subject_id = heard_current_subject());

-- Sessions: readable/updatable by their subject, or the single row matching the presented token hash;
-- creatable only for the authenticated subject.
DROP POLICY IF EXISTS heard_sessions_read ON heard_sessions;
CREATE POLICY heard_sessions_read ON heard_sessions FOR SELECT TO heard_api
 USING (subject_id = heard_current_subject() OR token_hash = heard_setting('session_hash'));
DROP POLICY IF EXISTS heard_sessions_create ON heard_sessions;
CREATE POLICY heard_sessions_create ON heard_sessions FOR INSERT TO heard_api
 WITH CHECK (subject_id = heard_current_subject());
DROP POLICY IF EXISTS heard_sessions_update ON heard_sessions;
CREATE POLICY heard_sessions_update ON heard_sessions FOR UPDATE TO heard_api
 USING (subject_id = heard_current_subject() OR token_hash = heard_setting('session_hash'))
 WITH CHECK (subject_id = heard_current_subject() OR token_hash = heard_setting('session_hash'));

-- Recovery credentials: same pattern keyed by the presented verifier.
DROP POLICY IF EXISTS heard_recovery_read ON heard_recovery_credentials;
CREATE POLICY heard_recovery_read ON heard_recovery_credentials FOR SELECT TO heard_api
 USING (subject_id = heard_current_subject() OR verifier = heard_setting('recovery_verifier'));
DROP POLICY IF EXISTS heard_recovery_create ON heard_recovery_credentials;
CREATE POLICY heard_recovery_create ON heard_recovery_credentials FOR INSERT TO heard_api
 WITH CHECK (subject_id = heard_current_subject());
DROP POLICY IF EXISTS heard_recovery_update ON heard_recovery_credentials;
CREATE POLICY heard_recovery_update ON heard_recovery_credentials FOR UPDATE TO heard_api
 USING (subject_id = heard_current_subject() OR verifier = heard_setting('recovery_verifier'))
 WITH CHECK (subject_id = heard_current_subject() OR verifier = heard_setting('recovery_verifier'));

DROP POLICY IF EXISTS heard_staff_self ON heard_staff_memberships;
CREATE POLICY heard_staff_self ON heard_staff_memberships FOR SELECT TO heard_api
 USING (subject_id = heard_current_subject());
DROP POLICY IF EXISTS heard_staff_operator ON heard_staff_memberships;
CREATE POLICY heard_staff_operator ON heard_staff_memberships FOR ALL TO heard_operator
 USING (heard_setting('operator_purpose') IS NOT NULL) WITH CHECK (heard_setting('operator_purpose') IS NOT NULL);

-- Audit: the API may append events attributed to the authenticated subject only.
GRANT INSERT ON heard_audit_events TO heard_api;
DROP POLICY IF EXISTS heard_audit_append_self ON heard_audit_events;
CREATE POLICY heard_audit_append_self ON heard_audit_events FOR INSERT TO heard_api
 WITH CHECK (actor_id = heard_current_subject() AND (case_id IS NULL OR EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id)));

COMMIT;
