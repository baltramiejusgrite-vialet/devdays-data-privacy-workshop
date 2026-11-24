-- Row level security on private_db.company.
-- A user sees only the companies listed in the session variable app.company_id,
-- one ID or a comma-separated list, for example:
--   SET app.company_id = '42';
--   SET app.company_id = '42,57';
-- Unset or empty means no rows. The workshop admin is a superuser and bypasses RLS.
-- Run as workshop after schema.sql and load_data.sql.

ALTER TABLE private_db.company ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS company_member_select ON private_db.company;

CREATE POLICY company_member_select ON private_db.company
    FOR SELECT
    USING (
        company_id = ANY (
            string_to_array(nullif(current_setting('app.company_id', true), ''), ',')::bigint[]
        )
    );

-- workshop_readonly reads company rows through this policy; it gets no other table.
GRANT USAGE ON SCHEMA private_db TO workshop_readonly;
GRANT SELECT ON private_db.company TO workshop_readonly;
