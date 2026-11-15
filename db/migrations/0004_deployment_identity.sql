-- HEARD-06: bind a database to exactly one deployment environment.
-- The runtime refuses readiness when HEARD_ENV differs from the bound value,
-- so staging and production resources cannot silently cross-connect.
BEGIN;
CREATE TABLE IF NOT EXISTS heard_deployment_identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 environment text NOT NULL CHECK(environment IN ('local','ci','staging','production')),
 bound_at timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION heard_reject_identity_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Deployment identity is immutable'; END $$;
DROP TRIGGER IF EXISTS heard_deployment_identity_immutable ON heard_deployment_identity;
CREATE TRIGGER heard_deployment_identity_immutable BEFORE UPDATE OR DELETE ON heard_deployment_identity
 FOR EACH ROW EXECUTE FUNCTION heard_reject_identity_change();
REVOKE ALL ON heard_deployment_identity FROM PUBLIC;
GRANT SELECT ON heard_deployment_identity TO heard_api, heard_job_worker, heard_public_projector;
-- The migrating (owner) role may drop into scoped roles per transaction (SET LOCAL ROLE),
-- without inheriting their privileges. Scoped roles themselves stay NOLOGIN/NOINHERIT.
GRANT heard_api, heard_job_worker, heard_public_projector TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
COMMIT;
