-- HEARD-09: versioned, append-only, purpose-specific consent events bound to the
-- exact policy text shown (SHA-256), with explicit recipient/asset scope.
BEGIN;
ALTER TABLE heard_consent_records DROP CONSTRAINT IF EXISTS heard_consent_records_purpose_check;
ALTER TABLE heard_consent_records ADD CONSTRAINT heard_consent_records_purpose_check
 CHECK(purpose IN ('private_processing','contact','helper_access','publication','identity_display','archive_replication'));
ALTER TABLE heard_consent_records ADD COLUMN IF NOT EXISTS sequence bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE heard_consent_records ADD COLUMN IF NOT EXISTS scope jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(scope)='object');
ALTER TABLE heard_consent_records ADD COLUMN IF NOT EXISTS policy_text_sha256 text CHECK(policy_text_sha256 IS NULL OR policy_text_sha256 ~ '^[a-f0-9]{64}$');
ALTER TABLE heard_consent_records ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS idx_heard_consent_sequence ON heard_consent_records(sequence);
-- Grants recorded from now on must be bound to the exact text the contributor saw.
ALTER TABLE heard_consent_records ADD CONSTRAINT heard_consent_grant_bound
 CHECK(decision <> 'grant' OR policy_text_sha256 IS NOT NULL) NOT VALID;

CREATE OR REPLACE FUNCTION heard_reject_consent_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Consent records are append-only'; END $$;
DROP TRIGGER IF EXISTS heard_consent_append_only ON heard_consent_records;
CREATE TRIGGER heard_consent_append_only BEFORE UPDATE OR DELETE ON heard_consent_records
 FOR EACH ROW EXECUTE FUNCTION heard_reject_consent_mutation();

-- Owners record and read consent on their own cases; assigned MFA staff may read it.
DROP POLICY IF EXISTS heard_consent_owner_read ON heard_consent_records;
CREATE POLICY heard_consent_owner_read ON heard_consent_records FOR SELECT TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id))));
DROP POLICY IF EXISTS heard_consent_owner_record ON heard_consent_records;
CREATE POLICY heard_consent_owner_record ON heard_consent_records FOR INSERT TO heard_api
 WITH CHECK (actor_id = heard_current_subject() AND EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));
COMMIT;
