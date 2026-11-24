-- Pseudonymise a copy of the database workshop's private_db with the slide-48 techniques,
-- so record linkage against public_db can be tested. Run in the privacy_pseudo database:
--   psql -v hmac_key=<random hex, never printed> -f pseudonymise_privacy_db.sql
--
-- Identifiers  -> keyed HMAC-SHA256 tokens (same value, same token: joins are kept)
-- Names        -> Person Anonymous;  birth date -> 2000-01-01
-- Salary/pay   -> 3500;  bonus, tax withheld, company profit -> 0
-- Everything else (city, postcode, street, role, department, company, dates) is copied
-- unchanged, exactly as the workshop technique table does — which is what the linkage
-- check is meant to expose.

\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS pgcrypto;

BEGIN;
SET LOCAL pseudo.key = :'hmac_key';            -- SET prints nothing, so the key never appears
SET LOCAL session_replication_role = replica;  -- foreign keys restored at COMMIT

CREATE FUNCTION pg_temp.tok(kind text, value text) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN value IS NULL THEN NULL
                ELSE kind || '-' || encode(hmac(kind || ':' || value, current_setting('pseudo.key'), 'sha256'), 'hex')
           END
$$;

UPDATE private_db.person_identity SET
    national_id = pg_temp.tok('nid', national_id),
    tax_id = pg_temp.tok('tax', tax_id),
    email = pg_temp.tok('email', email),
    phone = pg_temp.tok('phone', phone),
    first_name = 'Person Anonymous',
    last_name = 'Person Anonymous',
    date_of_birth = DATE '2000-01-01';

UPDATE private_db.employment_contract SET
    national_id = pg_temp.tok('nid', national_id),
    employee_email = pg_temp.tok('email', employee_email),
    manager_email = pg_temp.tok('email', manager_email),
    salary_eur = 3500,
    bonus_eur = 0;

UPDATE private_db.payroll_event SET
    employee_email = pg_temp.tok('email', employee_email),
    bank_account = pg_temp.tok('iban', bank_account),
    gross_pay_eur = 3500,
    tax_withheld_eur = 0;

UPDATE private_db.benefit_claim SET claimant_phone = pg_temp.tok('phone', claimant_phone);
UPDATE private_db.application_user SET email = pg_temp.tok('email', email);
UPDATE private_db.company SET annual_profit_eur = 0;

-- Abort if any relationship broke.
DO $$
DECLARE broken bigint;
BEGIN
    SELECT (SELECT count(*) FROM private_db.employment_contract e
             WHERE NOT EXISTS (SELECT 1 FROM private_db.person_identity p
                               WHERE p.national_id = e.national_id AND p.email = e.employee_email))
         + (SELECT count(*) FROM private_db.payroll_event x
             WHERE NOT EXISTS (SELECT 1 FROM private_db.person_identity p WHERE p.email = x.employee_email))
         + (SELECT count(*) FROM private_db.benefit_claim x
             WHERE NOT EXISTS (SELECT 1 FROM private_db.person_identity p WHERE p.phone = x.claimant_phone))
         + (SELECT count(*) FROM private_db.application_user x
             WHERE NOT EXISTS (SELECT 1 FROM private_db.person_identity p WHERE p.email = x.email))
      INTO broken;
    IF broken > 0 THEN
        RAISE EXCEPTION 'pseudonymisation broke % links; rolled back', broken;
    END IF;
END $$;
COMMIT;

SELECT 'people' AS table_name, count(*) FROM private_db.person_identity
UNION ALL SELECT 'contracts', count(*) FROM private_db.employment_contract
UNION ALL SELECT 'payroll events', count(*) FROM private_db.payroll_event;
