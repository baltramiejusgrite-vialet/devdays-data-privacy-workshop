-- Only the owner (workshop, the admin) may read the salaries table.
-- Revokes table and column access from PUBLIC and from every other role,
-- including any grants added later by hand. Run as workshop.

REVOKE ALL ON private_db.employment_contract FROM PUBLIC;
REVOKE ALL (salary_eur, bonus_eur) ON private_db.employment_contract FROM PUBLIC;

DO $$
DECLARE
    role_name name;
BEGIN
    FOR role_name IN
        SELECT rolname FROM pg_roles
        WHERE rolname NOT LIKE 'pg\_%' AND rolname <> 'workshop'
    LOOP
        EXECUTE format('REVOKE ALL ON private_db.employment_contract FROM %I', role_name);
        EXECUTE format('REVOKE ALL (salary_eur, bonus_eur) ON private_db.employment_contract FROM %I', role_name);
    END LOOP;
END
$$;
