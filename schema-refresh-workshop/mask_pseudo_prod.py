"""Exercise 3: mask non-key personal and financial fields in pseudo-prod with fixed values.

Usage (from schema-refresh-workshop):
    docker compose run --rm refresh-runner python mask_pseudo_prod.py apply
    docker compose run --rm refresh-runner python mask_pseudo_prod.py verify

Replacements (from the workshop slides):
    business.people.first_name         -> Person Anonymous
    business.people.last_name          -> Person Anonymous
    business.people.birth_date         -> 2000-01-01
    business.employment.salary_eur     -> 3500
    business.companies.annual_profit_eur -> 0

Names are not used as keys, so one shared value is safe. IDs, HMAC tokens and
relationships are untouched. All updates commit together; only a database named
pseudo-prod is accepted. Reruns update nothing once every value matches.
"""

import datetime as dt
import json
import os
import sys

import psycopg
from psycopg import sql

MASK_RULES = {
    ("people", "first_name"): "Person Anonymous",
    ("people", "last_name"): "Person Anonymous",
    ("people", "birth_date"): dt.date(2000, 1, 1),
    ("employment", "salary_eur"): 3500,
    ("companies", "annual_profit_eur"): 0,
}
SCHEMA = "business"
TARGET_DATABASE = "pseudo-prod"


class MaskingError(Exception):
    pass


def require_pseudo_prod(conn):
    name = conn.execute("SELECT current_database()").fetchone()[0]
    if name != TARGET_DATABASE:
        raise MaskingError(f"refusing to mask database {name!r}; only {TARGET_DATABASE!r} is allowed")


def count_unmasked(conn, rules=MASK_RULES):
    counts = {}
    for (table, column), value in rules.items():
        query = sql.SQL("SELECT count(*) FROM {t} WHERE {c} IS DISTINCT FROM %s").format(
            t=sql.Identifier(SCHEMA, table), c=sql.Identifier(column))
        counts[f"{table}.{column}"] = conn.execute(query, (value,)).fetchone()[0]
    return counts


def orphan_counts(conn):
    return {
        "orphaned_person_links": conn.execute(
            "SELECT count(*) FROM business.employment e WHERE NOT EXISTS "
            "(SELECT 1 FROM business.people p WHERE p.email = e.employee_email)").fetchone()[0],
        "orphaned_company_links": conn.execute(
            "SELECT count(*) FROM business.employment e WHERE NOT EXISTS "
            "(SELECT 1 FROM business.companies c WHERE c.company_id = e.company_id)").fetchone()[0],
    }


def mask_pseudo_prod(target, rules=MASK_RULES):
    """Applies every rule in one transaction on an open pseudo-prod connection. Returns rows changed."""
    require_pseudo_prod(target)
    changed = {}
    with target.transaction():
        for (table, column), value in rules.items():
            query = sql.SQL("UPDATE {t} SET {c} = %s WHERE {c} IS DISTINCT FROM %s").format(
                t=sql.Identifier(SCHEMA, table), c=sql.Identifier(column))
            changed[f"{table}.{column}"] = target.execute(query, (value, value)).rowcount
        if any(orphan_counts(target).values()):
            raise MaskingError("masking would break relationships; rolled back")
    return changed


def verify(target):
    require_pseudo_prod(target)
    unmasked = count_unmasked(target)
    return {"total_unmasked_values": sum(unmasked.values()), **orphan_counts(target), "per_column": unmasked}


def main(argv):
    if len(argv) != 2 or argv[1] not in ("apply", "verify"):
        sys.exit("usage: python mask_pseudo_prod.py apply|verify")
    try:
        with psycopg.connect(os.environ["PSEUDO_PROD_DSN"]) as target:
            if argv[1] == "apply":
                print(f"masked: {json.dumps(mask_pseudo_prod(target))}")
            result = verify(target)
    except MaskingError as err:
        sys.exit(f"FAIL: {err}")
    print(" ".join(f"{k}={v}" for k, v in result.items() if k != "per_column"))
    ok = result["total_unmasked_values"] == 0 and not result["orphaned_person_links"] \
        and not result["orphaned_company_links"]
    print("PASS: every masked field holds its fixed value" if ok else "FAIL: unmasked values remain")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv)
