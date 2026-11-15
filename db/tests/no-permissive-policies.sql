-- Run in a disposable PostgreSQL database after all migrations.
-- Every RLS policy on a HEARD table must be (1) on the reviewed allowlist below,
-- (2) granted only to scoped NOLOGIN roles, never PUBLIC, and (3) bound to the
-- authenticated subject or a presented lookup secret (heard_current_subject /
-- heard_setting). Unconditional (`true`) policies are rejected. Tables with no
-- policy remain default-deny under FORCE ROW LEVEL SECURITY.
DO $$
DECLARE p record;
DECLARE reviewed text[] := ARRAY[
  'heard_subjects.heard_subjects_self',
  'heard_subjects.heard_subjects_operator',
  'heard_profiles.heard_profiles_self',
  'heard_sessions.heard_sessions_read',
  'heard_sessions.heard_sessions_create',
  'heard_sessions.heard_sessions_update',
  'heard_recovery_credentials.heard_recovery_read',
  'heard_recovery_credentials.heard_recovery_create',
  'heard_recovery_credentials.heard_recovery_update',
  'heard_staff_memberships.heard_staff_self',
  'heard_staff_memberships.heard_staff_operator',
  'heard_audit_events.heard_audit_append_self',
  'heard_case_assignments.heard_assignments_self',
  'heard_case_assignments.heard_assignments_operator',
  'heard_cases.heard_cases_operator',
  'heard_cases.heard_cases_owner_read',
  'heard_cases.heard_cases_owner_create',
  'heard_cases.heard_cases_owner_update',
  'heard_cases.heard_cases_assigned_read',
  'heard_cases.heard_cases_assigned_review',
  'heard_case_events.heard_case_events_visible',
  'heard_case_events.heard_case_events_append',
  'heard_private_objects.heard_objects_visible',
  'heard_private_objects.heard_objects_owner_insert',
  'heard_resource_grants.heard_grants_visible',
  'heard_resource_grants.heard_grants_create',
  'heard_resource_grants.heard_grants_revoke',
  'heard_consent_records.heard_consent_owner_read',
  'heard_consent_records.heard_consent_owner_record',
  'heard_intake_drafts.heard_drafts_owner_read',
  'heard_intake_drafts.heard_drafts_owner_create',
  'heard_intake_drafts.heard_drafts_owner_update',
  'heard_intake_drafts.heard_drafts_owner_delete',
  'heard_intake_drafts.heard_drafts_expiry_purge',
  'heard_submission_receipts.heard_receipts_owner_read',
  'heard_submission_receipts.heard_receipts_owner_create',
  'heard_cases.heard_cases_expiry_withdraw',
  'heard_cases.heard_cases_expiry_read'
];
DECLARE scoped name[] := ARRAY['heard_api','heard_job_worker','heard_public_projector','heard_operator']::name[];
BEGIN
 FOR p IN SELECT tablename, policyname, roles, qual, with_check, permissive FROM pg_policies WHERE schemaname = current_schema() AND tablename LIKE 'heard\_%' LOOP
   IF NOT (p.tablename || '.' || p.policyname) = ANY(reviewed) THEN
     RAISE EXCEPTION 'Unreviewed RLS policy %.%', p.tablename, p.policyname;
   END IF;
   IF 'public' = ANY(p.roles) OR NOT (p.roles <@ scoped) THEN
     RAISE EXCEPTION 'Policy %.% must target scoped roles only', p.tablename, p.policyname;
   END IF;
   IF coalesce(p.qual, '') ~* '^\s*\(?\s*true\s*\)?\s*$' OR coalesce(p.with_check, '') ~* '^\s*\(?\s*true\s*\)?\s*$' THEN
     RAISE EXCEPTION 'Unconditional policy %.%', p.tablename, p.policyname;
   END IF;
   IF coalesce(p.qual, '') !~ '(heard_current_subject|heard_setting|heard_assigned|heard_draft_expired)' AND coalesce(p.with_check, '') !~ '(heard_current_subject|heard_setting|heard_assigned|heard_draft_expired)' THEN
     RAISE EXCEPTION 'Policy %.% is not bound to a subject or presented secret', p.tablename, p.policyname;
   END IF;
 END LOOP;
 -- Tables that must stay default-deny (no policy at all) until their owning unit reviews access.
 IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = current_schema() AND tablename IN ('heard_jobs','heard_publications')) THEN
   RAISE EXCEPTION 'Jobs and publications must remain default-deny';
 END IF;
END $$;
