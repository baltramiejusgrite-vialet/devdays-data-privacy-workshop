-- Average salary for the caller's own company.
-- The caller must set the session variable first, for example:
--   SET app.company_id = '42';
-- If app.company_id was never set in the session, reading the view raises
-- "unrecognized configuration parameter"; if it was reset to empty, the cast fails.

CREATE OR REPLACE VIEW private_db.my_company_average_salary AS
SELECT
    c.company_id,
    c.registration_number,
    c.company_name,
    count(e.contract_id) AS contract_count,
    round(avg(e.salary_eur), 2) AS average_salary_eur
FROM private_db.company AS c
LEFT JOIN private_db.employment_contract AS e
    ON e.company_registration_number = c.registration_number
WHERE c.company_id = current_setting('app.company_id')::bigint
GROUP BY c.company_id, c.registration_number, c.company_name;

-- workshop_readonly may read this view and nothing else.
-- The view runs with its owner's rights, so it still reads the base tables.
ALTER DEFAULT PRIVILEGES FOR ROLE workshop IN SCHEMA private_db, public_db REVOKE SELECT ON TABLES FROM workshop_readonly;
REVOKE ALL ON ALL TABLES IN SCHEMA private_db, public_db FROM workshop_readonly;
REVOKE USAGE ON SCHEMA public_db FROM workshop_readonly;
GRANT USAGE ON SCHEMA private_db TO workshop_readonly;
GRANT SELECT ON private_db.my_company_average_salary TO workshop_readonly;
