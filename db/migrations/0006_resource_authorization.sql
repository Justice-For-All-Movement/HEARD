-- HEARD-08: database-side deny-by-default resource access.
-- Owners reach their own cases; assigned staff reach assigned cases only with an
-- MFA-verified session (heard.assurance setting); helpers reach individually granted
-- objects only while the grant is active. Everything else stays invisible.
BEGIN;

CREATE TABLE IF NOT EXISTS heard_case_assignments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 case_id uuid NOT NULL REFERENCES heard_cases(id),
 staff_subject_id uuid NOT NULL REFERENCES heard_subjects(id),
 role text NOT NULL CHECK(role IN ('reviewer','editor','safety')),
 purpose text NOT NULL CHECK(char_length(trim(purpose)) BETWEEN 3 AND 200),
 assigned_by uuid REFERENCES heard_subjects(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK(expires_at > created_at),
 CHECK(assigned_by IS NULL OR assigned_by <> staff_subject_id)
);
CREATE INDEX IF NOT EXISTS idx_heard_assignments_staff ON heard_case_assignments(staff_subject_id, case_id) WHERE revoked_at IS NULL;

-- Nobody may be assigned to review their own case.
CREATE OR REPLACE FUNCTION heard_reject_self_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = NEW.case_id AND c.subject_id = NEW.staff_subject_id) THEN
  RAISE EXCEPTION 'Staff cannot be assigned to their own case' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS heard_assignment_not_owner ON heard_case_assignments;
CREATE TRIGGER heard_assignment_not_owner BEFORE INSERT OR UPDATE ON heard_case_assignments
 FOR EACH ROW EXECUTE FUNCTION heard_reject_self_assignment();

ALTER TABLE heard_case_assignments ENABLE ROW LEVEL SECURITY; ALTER TABLE heard_case_assignments FORCE ROW LEVEL SECURITY;
REVOKE ALL ON heard_case_assignments FROM PUBLIC;

-- Active assignment for the current, MFA-verified staff subject.
CREATE OR REPLACE FUNCTION heard_assigned(target_case uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT heard_setting('assurance') = 'staff_mfa' AND EXISTS (
  SELECT 1 FROM heard_case_assignments a
  WHERE a.case_id = target_case AND a.staff_subject_id = heard_current_subject()
    AND a.revoked_at IS NULL AND a.expires_at > now())
$$;
REVOKE ALL ON FUNCTION heard_assigned(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION heard_assigned(uuid) TO heard_api, heard_operator;

GRANT SELECT ON heard_case_assignments TO heard_api;
GRANT SELECT, INSERT ON heard_case_assignments TO heard_operator;
GRANT UPDATE (revoked_at) ON heard_case_assignments TO heard_operator;
GRANT SELECT ON heard_cases TO heard_operator;
GRANT UPDATE (status, updated_at) ON heard_cases TO heard_api;
GRANT UPDATE (revoked_at) ON heard_resource_grants TO heard_api;

-- Assignments: staff see their own; the operator manages them with a declared purpose.
DROP POLICY IF EXISTS heard_assignments_self ON heard_case_assignments;
CREATE POLICY heard_assignments_self ON heard_case_assignments FOR SELECT TO heard_api
 USING (staff_subject_id = heard_current_subject());
DROP POLICY IF EXISTS heard_assignments_operator ON heard_case_assignments;
CREATE POLICY heard_assignments_operator ON heard_case_assignments FOR ALL TO heard_operator
 USING (heard_setting('operator_purpose') IS NOT NULL) WITH CHECK (heard_setting('operator_purpose') IS NOT NULL);
DROP POLICY IF EXISTS heard_cases_operator ON heard_cases;
CREATE POLICY heard_cases_operator ON heard_cases FOR SELECT TO heard_operator
 USING (heard_setting('operator_purpose') IS NOT NULL);

-- Case status may only move along the workflow state machine (mirrors @heard/secure-intake).
CREATE OR REPLACE FUNCTION heard_enforce_case_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.subject_id IS DISTINCT FROM OLD.subject_id OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.visibility IS DISTINCT FROM OLD.visibility THEN
  RAISE EXCEPTION 'Case ownership, kind and visibility are immutable' USING ERRCODE = '23514';
 END IF;
 IF NEW.status IS DISTINCT FROM OLD.status AND NOT (OLD.status, NEW.status) IN (
   ('draft','submitted'), ('draft','withdrawn'), ('submitted','review'), ('submitted','withdrawn'), ('review','closed'), ('review','withdrawn')) THEN
  RAISE EXCEPTION 'Invalid case transition' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS heard_case_transition ON heard_cases;
CREATE TRIGGER heard_case_transition BEFORE UPDATE ON heard_cases FOR EACH ROW EXECUTE FUNCTION heard_enforce_case_transition();

-- Cases: owners create private drafts, read their cases and submit/withdraw; assigned MFA staff read and review.
DROP POLICY IF EXISTS heard_cases_owner_read ON heard_cases;
CREATE POLICY heard_cases_owner_read ON heard_cases FOR SELECT TO heard_api
 USING (subject_id = heard_current_subject());
DROP POLICY IF EXISTS heard_cases_owner_create ON heard_cases;
CREATE POLICY heard_cases_owner_create ON heard_cases FOR INSERT TO heard_api
 WITH CHECK (subject_id = heard_current_subject() AND status = 'draft' AND visibility = 'private');
DROP POLICY IF EXISTS heard_cases_owner_update ON heard_cases;
CREATE POLICY heard_cases_owner_update ON heard_cases FOR UPDATE TO heard_api
 USING (subject_id = heard_current_subject()) WITH CHECK (subject_id = heard_current_subject() AND status IN ('submitted','withdrawn'));
DROP POLICY IF EXISTS heard_cases_assigned_read ON heard_cases;
CREATE POLICY heard_cases_assigned_read ON heard_cases FOR SELECT TO heard_api
 USING (heard_assigned(id));
DROP POLICY IF EXISTS heard_cases_assigned_review ON heard_cases;
CREATE POLICY heard_cases_assigned_review ON heard_cases FOR UPDATE TO heard_api
 USING (heard_assigned(id)) WITH CHECK (heard_assigned(id) AND status IN ('review','closed','withdrawn'));

-- Case events: visible/insertable for cases the subject can see; attribution must be the subject.
DROP POLICY IF EXISTS heard_case_events_visible ON heard_case_events;
CREATE POLICY heard_case_events_visible ON heard_case_events FOR SELECT TO heard_api
 USING (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id))));
DROP POLICY IF EXISTS heard_case_events_append ON heard_case_events;
CREATE POLICY heard_case_events_append ON heard_case_events FOR INSERT TO heard_api
 WITH CHECK (actor_id = heard_current_subject() AND EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id))));

-- Private objects: owner, assigned staff, or the recipient of an active, unexpired grant for that exact object.
DROP POLICY IF EXISTS heard_objects_visible ON heard_private_objects;
CREATE POLICY heard_objects_visible ON heard_private_objects FOR SELECT TO heard_api
 USING (
  EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND (c.subject_id = heard_current_subject() OR heard_assigned(c.id)))
  OR EXISTS (SELECT 1 FROM heard_resource_grants g WHERE g.object_id = heard_private_objects.id AND g.case_id = heard_private_objects.case_id
             AND g.recipient_id = heard_current_subject() AND g.revoked_at IS NULL AND g.expires_at > now()));
DROP POLICY IF EXISTS heard_objects_owner_insert ON heard_private_objects;
CREATE POLICY heard_objects_owner_insert ON heard_private_objects FOR INSERT TO heard_api
 WITH CHECK (EXISTS (SELECT 1 FROM heard_cases c WHERE c.id = case_id AND c.subject_id = heard_current_subject()));

-- Grants: created/revoked by the case owner (grantor); visible to grantor and recipient.
DROP POLICY IF EXISTS heard_grants_visible ON heard_resource_grants;
CREATE POLICY heard_grants_visible ON heard_resource_grants FOR SELECT TO heard_api
 USING (grantor_id = heard_current_subject() OR recipient_id = heard_current_subject());
DROP POLICY IF EXISTS heard_grants_create ON heard_resource_grants;
CREATE POLICY heard_grants_create ON heard_resource_grants FOR INSERT TO heard_api
 WITH CHECK (grantor_id = heard_current_subject() AND recipient_id <> heard_current_subject());
DROP POLICY IF EXISTS heard_grants_revoke ON heard_resource_grants;
CREATE POLICY heard_grants_revoke ON heard_resource_grants FOR UPDATE TO heard_api
 USING (grantor_id = heard_current_subject()) WITH CHECK (grantor_id = heard_current_subject());

COMMIT;
