-- Row level security on private_db.company.
-- A user sees only the companies listed in the session variable app.company_id,
-- one ID or a comma-separated list, for example:
--   SET app.company_id = '42';
--   SET app.company_id = '42,57';
-- Querying the table without setting it (or with it empty) raises a
-- permission error (SQLSTATE 42501). The workshop admin is a superuser and
-- bypasses RLS. Run as workshop after schema.sql and load_data.sql.

CREATE OR REPLACE FUNCTION private_db.session_company_ids()
RETURNS bigint[]
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    raw text := nullif(current_setting('app.company_id', true), '');
BEGIN
    IF raw IS NULL THEN
        RAISE EXCEPTION 'permission denied for table company: set app.company_id first'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN string_to_array(raw, ',')::bigint[];
END
$$;

ALTER TABLE private_db.company ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS company_member_select ON private_db.company;

CREATE POLICY company_member_select ON private_db.company
    FOR SELECT
    USING (company_id = ANY (private_db.session_company_ids()));

-- workshop_readonly reads company rows through this policy; it gets no other table.
GRANT USAGE ON SCHEMA private_db TO workshop_readonly;
GRANT SELECT ON private_db.company TO workshop_readonly;
GRANT EXECUTE ON FUNCTION private_db.session_company_ids() TO workshop_readonly;
