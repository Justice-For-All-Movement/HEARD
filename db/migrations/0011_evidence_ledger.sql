-- HEARD-14: immutable originals and a per-object, hash-chained, append-only
-- chain-of-handling ledger. The chain is computed by the database on insert, so
-- no writer can choose its own predecessor or hash.
BEGIN;
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS ledger_head text CHECK(ledger_head IS NULL OR ledger_head ~ '^[a-f0-9]{64}$');
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS ledger_length integer NOT NULL DEFAULT 0 CHECK(ledger_length >= 0);
ALTER TABLE heard_private_objects ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES heard_subjects(id);

-- Originals are immutable: identity, location, digest, size and declared type never change.
CREATE OR REPLACE FUNCTION heard_reject_original_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.case_id IS DISTINCT FROM OLD.case_id OR NEW.storage_ref IS DISTINCT FROM OLD.storage_ref
    OR NEW.checksum_sha256 IS DISTINCT FROM OLD.checksum_sha256 OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
    OR NEW.declared_type IS DISTINCT FROM OLD.declared_type OR NEW.upload_session_id IS DISTINCT FROM OLD.upload_session_id
    OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
  RAISE EXCEPTION 'Evidence originals are immutable' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS heard_original_immutable ON heard_private_objects;
CREATE TRIGGER heard_original_immutable BEFORE UPDATE ON heard_private_objects FOR EACH ROW EXECUTE FUNCTION heard_reject_original_mutation();
DROP TRIGGER IF EXISTS heard_original_no_delete ON heard_private_objects;
CREATE OR REPLACE FUNCTION heard_reject_original_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Evidence originals cannot be deleted here; use the retention process' USING ERRCODE = '23514'; END $$;
CREATE TRIGGER heard_original_no_delete BEFORE DELETE ON heard_private_objects FOR EACH ROW EXECUTE FUNCTION heard_reject_original_delete();

CREATE TABLE IF NOT EXISTS heard_evidence_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 object_id uuid NOT NULL REFERENCES heard_private_objects(id),
 case_id uuid NOT NULL REFERENCES heard_cases(id),
 ordinal integer NOT NULL CHECK(ordinal >= 1),
 operation text NOT NULL CHECK(operation IN ('received','scan_cleared','scan_rejected','downloaded','verified','verification_failed','source_asserted','manifest_exported')),
 actor_kind text NOT NULL CHECK(actor_kind IN ('contributor','staff','helper','service')),
 actor_id uuid REFERENCES heard_subjects(id),
 detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(detail) = 'object' AND pg_column_size(detail) < 2048),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 prev_hash text CHECK(prev_hash IS NULL OR prev_hash ~ '^[a-f0-9]{64}$'),
 event_hash text NOT NULL CHECK(event_hash ~ '^[a-f0-9]{64}$'),
 UNIQUE(object_id, ordinal),
 CHECK((actor_kind = 'service') = (actor_id IS NULL))
);

-- Canonical text hashed into the chain (also recomputed by the application verifier).
CREATE OR REPLACE FUNCTION heard_evidence_event_hash(prev text, object_id uuid, case_id uuid, ordinal integer, operation text, actor_kind text, actor_id uuid, detail jsonb, recorded_at timestamptz)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT encode(sha256(convert_to(concat_ws('|', 'heard-ledger-v1', coalesce(prev, ''), object_id::text, case_id::text, ordinal::text, operation, actor_kind,
   coalesce(actor_id::text, ''), detail::text, to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')), 'UTF8')), 'hex')
$$;

CREATE OR REPLACE FUNCTION heard_chain_evidence_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE head text; len integer; owner_case uuid;
BEGIN
 SELECT o.ledger_head, o.ledger_length, o.case_id INTO head, len, owner_case FROM heard_private_objects o WHERE o.id = NEW.object_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Evidence object not visible' USING ERRCODE = '42501'; END IF;
 IF owner_case IS DISTINCT FROM NEW.case_id THEN RAISE EXCEPTION 'Event case does not match object' USING ERRCODE = '23514'; END IF;
 -- The actor kind is derived, never trusted from the writer.
 IF NEW.actor_kind <> 'service' THEN
  NEW.actor_kind := CASE
   WHEN EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = NEW.case_id AND c.subject_id = NEW.actor_id) THEN 'contributor'
   WHEN heard_assigned(NEW.case_id) THEN 'staff'
   ELSE 'helper' END;
 END IF;
 NEW.ordinal := len + 1;
 NEW.prev_hash := head;
 NEW.recorded_at := date_trunc('microseconds', clock_timestamp());
 NEW.event_hash := heard_evidence_event_hash(head, NEW.object_id, NEW.case_id, NEW.ordinal, NEW.operation, NEW.actor_kind, NEW.actor_id, NEW.detail, NEW.recorded_at);
 UPDATE heard_private_objects SET ledger_head = NEW.event_hash, ledger_length = NEW.ordinal WHERE id = NEW.object_id;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS heard_evidence_chain ON heard_evidence_events;
CREATE TRIGGER heard_evidence_chain BEFORE INSERT ON heard_evidence_events FOR EACH ROW EXECUTE FUNCTION heard_chain_evidence_event();
CREATE OR REPLACE FUNCTION heard_reject_evidence_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Evidence handling events are append-only'; END $$;
DROP TRIGGER IF EXISTS heard_evidence_append_only ON heard_evidence_events;
CREATE TRIGGER heard_evidence_append_only BEFORE UPDATE OR DELETE ON heard_evidence_events FOR EACH ROW EXECUTE FUNCTION heard_reject_evidence_event_mutation();

ALTER TABLE heard_evidence_events ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_evidence_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON heard_evidence_events FROM PUBLIC;
REVOKE ALL ON FUNCTION heard_evidence_event_hash(text, uuid, uuid, integer, text, text, uuid, jsonb, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION heard_evidence_event_hash(text, uuid, uuid, integer, text, text, uuid, jsonb, timestamptz) TO heard_api, heard_job_worker;
GRANT SELECT, INSERT ON heard_evidence_events TO heard_api, heard_job_worker;
GRANT UPDATE (ledger_head, ledger_length) ON heard_private_objects TO heard_api, heard_job_worker;

-- Ledger head updates (via the chaining trigger) are allowed for whoever can see the object;
-- column grants restrict them to the two ledger columns, and the immutability trigger guards the rest.
DROP POLICY IF EXISTS heard_objects_ledger_advance ON heard_private_objects;
CREATE POLICY heard_objects_ledger_advance ON heard_private_objects FOR UPDATE TO heard_api
 USING (
  EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id)))
  OR EXISTS (SELECT 1 FROM heard_resource_grants g WHERE g.object_id = heard_private_objects.id AND g.case_id = heard_private_objects.case_id
             AND g.recipient_id = heard_current_subject() AND g.revoked_at IS NULL AND g.expires_at > now()))
 WITH CHECK (
  EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id)))
  OR EXISTS (SELECT 1 FROM heard_resource_grants g WHERE g.object_id = heard_private_objects.id AND g.case_id = heard_private_objects.case_id
             AND g.recipient_id = heard_current_subject() AND g.revoked_at IS NULL AND g.expires_at > now()));

-- Events: the case owner and assigned MFA staff read the full ledger; anyone who can
-- see the object appends events attributed to themselves; the scan worker appends service events.
DROP POLICY IF EXISTS heard_evidence_events_read ON heard_evidence_events;
CREATE POLICY heard_evidence_events_read ON heard_evidence_events FOR SELECT TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id))));
DROP POLICY IF EXISTS heard_evidence_events_append ON heard_evidence_events;
CREATE POLICY heard_evidence_events_append ON heard_evidence_events FOR INSERT TO heard_api
 WITH CHECK (actor_id = heard_current_subject() AND actor_kind IN ('contributor','staff','helper')
  AND EXISTS (SELECT 1 FROM heard_private_objects o WHERE o.id = object_id));
DROP POLICY IF EXISTS heard_evidence_events_service ON heard_evidence_events;
CREATE POLICY heard_evidence_events_service ON heard_evidence_events FOR ALL TO heard_job_worker
 USING (heard_scan_target(object_id))
 WITH CHECK (heard_scan_target(object_id) AND actor_kind = 'service' AND operation IN ('scan_cleared','scan_rejected'));
COMMIT;
