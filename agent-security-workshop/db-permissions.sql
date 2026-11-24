-- Database permissions for the gateway (steps 5 and 6). Safe to run repeatedly.
-- Runs automatically on a fresh database (mounted into docker-entrypoint-initdb.d)
-- and can be re-applied as lab_admin:
--   docker compose exec -T db psql -v ON_ERROR_STOP=1 -U lab_admin -d agent_lab -f /docker-entrypoint-initdb.d/02-permissions.sql
--
-- lab_gateway        login used by the gateway; no table access, EXECUTE on the aggregate only
-- layer_row_reader   NOLOGIN owner of the functions; the only role that reads salary rows

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

-- Nobody reads the private schema except the function owner.
REVOKE ALL ON SCHEMA lab_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA lab_private FROM PUBLIC, lab_gateway;
GRANT USAGE ON SCHEMA lab_private TO layer_row_reader;
GRANT SELECT ON lab_private.employee_salaries TO layer_row_reader;

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

ALTER FUNCTION lab_api.salary_rows(integer) OWNER TO layer_row_reader;
ALTER FUNCTION lab_api.company_salary_summary(integer) OWNER TO layer_row_reader;

REVOKE ALL ON FUNCTION lab_api.salary_rows(integer) FROM PUBLIC, lab_gateway;
REVOKE ALL ON FUNCTION lab_api.company_salary_summary(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lab_api.company_salary_summary(integer) TO lab_gateway;

-- Gateway login: connect, call the aggregate, read public projects. Nothing else.
GRANT CONNECT ON DATABASE agent_lab TO lab_gateway;
GRANT USAGE ON SCHEMA lab_api, lab_public TO lab_gateway;
GRANT SELECT ON lab_public.projects TO lab_gateway;
