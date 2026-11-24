-- Database permissions for the gateway (steps 5, 6 and 7). Safe to run repeatedly.
-- Runs automatically on a fresh database (mounted into docker-entrypoint-initdb.d)
-- and can be re-applied as lab_admin:
--   docker compose exec -T db psql -v ON_ERROR_STOP=1 -U lab_admin -d agent_lab -f /docker-entrypoint-initdb.d/02-permissions.sql
--
-- lab_gateway        login used by the gateway; no table access, EXECUTE on the token functions only
-- layer_row_reader   NOLOGIN owner of the functions; the only role that reads salary rows and tokens

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'layer_row_reader') THEN
        CREATE ROLE layer_row_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lab_gateway') THEN
        CREATE ROLE lab_gateway LOGIN PASSWORD 'gateway-demo';
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS lab_api;

-- Step 7: access tokens. Only a SHA-256 hash is stored; the token itself is never in the database.
-- Each token is bound to one actor and one company; that binding is the only source of permissions.
CREATE TABLE IF NOT EXISTS lab_private.access_tokens (
    token_sha256 bytea PRIMARY KEY,
    actor text NOT NULL,
    company_id integer NOT NULL,
    expires_at timestamptz NOT NULL
);

-- Nobody reads the private schema except the function owner.
REVOKE ALL ON SCHEMA lab_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA lab_private FROM PUBLIC, lab_gateway;
GRANT USAGE ON SCHEMA lab_private TO layer_row_reader;
GRANT SELECT ON lab_private.employee_salaries TO layer_row_reader;
GRANT SELECT ON lab_private.access_tokens TO layer_row_reader;

-- Step 5 function: individual rows. Kept for reference, but nobody may execute it.
CREATE OR REPLACE FUNCTION lab_api.salary_rows(p_company_id integer)
RETURNS TABLE (company_id integer, employee_id integer, salary_eur integer)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.company_id, s.employee_id, s.salary_eur
    FROM lab_private.employee_salaries AS s
    WHERE s.company_id = p_company_id
$$;

-- Step 6 function: one aggregate row per company, no individual values.
CREATE OR REPLACE FUNCTION lab_api.company_salary_summary(p_company_id integer)
RETURNS TABLE (company_id integer, employee_count bigint, average_salary_eur numeric)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p_company_id, count(*), round(avg(s.salary_eur), 2)
    FROM lab_private.employee_salaries AS s
    WHERE s.company_id = p_company_id
$$;

-- Step 7: verified identity. Returns the token's actor and company, or no row.
CREATE OR REPLACE FUNCTION lab_api.authenticate(p_token text)
RETURNS TABLE (actor text, company_id integer)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT t.actor, t.company_id
    FROM lab_private.access_tokens AS t
    WHERE t.token_sha256 = sha256(convert_to(p_token, 'UTF8'))
      AND t.expires_at > now()
$$;

-- Step 7: the summary, but only for the company the token is bound to.
-- Invalid token: SQLSTATE 28000. Valid token, other company: SQLSTATE 42501.
CREATE OR REPLACE FUNCTION lab_api.salary_summary(p_token text, p_company_id integer)
RETURNS TABLE (company_id integer, employee_count bigint, average_salary_eur numeric)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_company_id integer;
BEGIN
    SELECT a.company_id INTO v_company_id FROM lab_api.authenticate(p_token) AS a;
    IF v_company_id IS NULL THEN
        RAISE EXCEPTION 'invalid or expired token' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    IF v_company_id IS DISTINCT FROM p_company_id THEN
        RAISE EXCEPTION 'token is not valid for this company' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
        SELECT p_company_id, count(*), round(avg(s.salary_eur), 2)
        FROM lab_private.employee_salaries AS s
        WHERE s.company_id = p_company_id;
END
$$;

ALTER FUNCTION lab_api.salary_rows(integer) OWNER TO layer_row_reader;
ALTER FUNCTION lab_api.company_salary_summary(integer) OWNER TO layer_row_reader;
ALTER FUNCTION lab_api.authenticate(text) OWNER TO layer_row_reader;
ALTER FUNCTION lab_api.salary_summary(text, integer) OWNER TO layer_row_reader;
GRANT USAGE ON SCHEMA lab_api TO layer_row_reader;

-- Step 6's open summary (any company, no identity) and step 5's rows: nobody may execute them.
REVOKE ALL ON FUNCTION lab_api.salary_rows(integer) FROM PUBLIC, lab_gateway;
REVOKE ALL ON FUNCTION lab_api.company_salary_summary(integer) FROM PUBLIC, lab_gateway;
-- Step 7: the gateway may only use the token-checked functions.
REVOKE ALL ON FUNCTION lab_api.authenticate(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lab_api.salary_summary(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lab_api.authenticate(text) TO lab_gateway;
GRANT EXECUTE ON FUNCTION lab_api.salary_summary(text, integer) TO lab_gateway;

-- Gateway login: connect, call the aggregate, read public projects. Nothing else.
GRANT CONNECT ON DATABASE agent_lab TO lab_gateway;
GRANT USAGE ON SCHEMA lab_api, lab_public TO lab_gateway;
GRANT SELECT ON lab_public.projects TO lab_gateway;
