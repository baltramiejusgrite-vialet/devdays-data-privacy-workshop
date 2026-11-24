"""Exercise 5: one command that rebuilds pseudo-prod from production safely.

Usage (from schema-refresh-workshop):
    docker compose run --rm refresh-runner python refresh_pseudo_prod.py
or the workshop snippet:
    sh snippets/refresh-pseudo-prod.sh

Steps, each one stopping the refresh on failure:
  1. Schema check: production vs the code-defined schema (pseudo_prod_schema.py).
     On any difference: print what differs, save artifacts/refresh/schema.diff,
     exit 2, and leave pseudo-prod untouched.
  2. Clone production into a private staging database (pseudo-prod-staging) with
     pg_dump / pg_restore. The source is only read.
  3. Tokenize emails and national IDs with the existing HMAC key (tokenize_pseudo_prod).
  4. Mask names, birth dates, salaries and profits (mask_pseudo_prod rules).
  5. Validate the staging copy: zero non-keyed values, zero unmasked values, no
     original identifiers, no broken links, row counts equal to production.
  6. Replace pseudo-prod: rename the old one aside, rename staging into place, drop the old one.
Other failures exit 1 and remove the staging database. Success exits 0.
No key, token or personal value is printed.
"""

import os
import subprocess
import sys
import urllib.parse
from pathlib import Path

import psycopg
from psycopg import sql

import mask_pseudo_prod
import tokenize_pseudo_prod as tok
from describe_schema import render_schema
from pseudo_prod_schema import business_schema, expected_description, mask_rules, schema_differences
import compare_schemas

TARGET = "pseudo-prod"
STAGING = "pseudo-prod-staging"
RETIRED = "pseudo-prod-retired"
ARTIFACTS = Path(os.environ.get("REFRESH_ARTIFACTS", "artifacts/refresh"))


class RefreshStopped(Exception):
    """Schema mismatch: nothing was changed."""


class RefreshFailed(Exception):
    pass


def dsn_for(dsn, database):
    parts = urllib.parse.urlsplit(dsn)
    return urllib.parse.urlunsplit(parts._replace(path="/" + urllib.parse.quote(database)))


def log(message):
    print(message, flush=True)


# --- steps ------------------------------------------------------------------------------


def check_schema(source_admin_dsn):
    with psycopg.connect(source_admin_dsn, autocommit=True) as conn:
        live = business_schema(conn)
    problems = schema_differences(live)
    if problems:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        diff = compare_schemas.compare(expected_description(), render_schema(live),
                                       "pseudo-prod (defined in code)", "production")
        (ARTIFACTS / "schema.diff").write_text(diff, encoding="utf-8")
        raise RefreshStopped("\n".join(f"  - {p}" for p in problems))
    log("1/6 PASS: production schema matches the pseudo-prod schema defined in code")


def server_dsn(target_dsn):
    return dsn_for(target_dsn, "postgres")


def database_exists(admin, name):
    return admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone() is not None


def drop_database(admin, name):
    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))


def clone_to_staging(source_admin_dsn, target_dsn):
    with psycopg.connect(server_dsn(target_dsn), autocommit=True) as admin:
        drop_database(admin, STAGING)
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(STAGING)))
        admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(STAGING)))
    dump = subprocess.run(["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--dbname", source_admin_dsn],
                          capture_output=True, check=False)
    if dump.returncode:
        raise RefreshFailed("pg_dump of production failed")
    restore = subprocess.run(["pg_restore", "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl",
                              "--dbname", dsn_for(target_dsn, STAGING)], input=dump.stdout, capture_output=True)
    if restore.returncode:
        raise RefreshFailed("pg_restore into staging failed")
    log("2/6 PASS: production cloned into private staging database")


def tokenize_staging(source_dsn, staging_dsn, key):
    result = tok.tokenize(source_dsn, staging_dsn, key)
    log(f"3/6 PASS: {result['updated_values']} email and national-ID values replaced with HMAC tokens")


def mask_staging(staging_dsn):
    with psycopg.connect(staging_dsn) as conn:
        changed = {}
        with conn.transaction():
            for (table, column), value in mask_rules().items():
                query = sql.SQL("UPDATE {t} SET {c} = %s WHERE {c} IS DISTINCT FROM %s").format(
                    t=sql.Identifier("business", table), c=sql.Identifier(column))
                changed[f"{table}.{column}"] = conn.execute(query, (value, value)).rowcount
    log(f"4/6 PASS: {sum(changed.values())} name, birth date, salary and profit values masked")


def validate_staging(source_dsn, staging_dsn, key):
    tokens = tok.verify(source_dsn, staging_dsn, key)
    with psycopg.connect(staging_dsn) as conn:
        unmasked = sum(mask_pseudo_prod.count_unmasked(conn, mask_rules()).values())
        orphans = mask_pseudo_prod.orphan_counts(conn)
        staged_counts = {t: conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier("business", t)))
                         .fetchone()[0] for t in ("companies", "employment", "people")}
        staged_schema = business_schema(conn)
    with psycopg.connect(source_dsn) as conn:
        source_counts = {t: conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier("business", t)))
                         .fetchone()[0] for t in ("companies", "employment", "people")}
    checks = {
        "non_keyed_values": tokens["non_keyed_values"],
        "remaining_original_values": tokens["remaining_original_values"],
        "unmasked_values": unmasked,
        "orphaned_links": tokens["orphaned_employment_links"] + sum(orphans.values()),
        "row_count_mismatches": sum(staged_counts[t] != source_counts[t] for t in source_counts),
        "schema_differences": len(schema_differences(staged_schema)),
    }
    failed = {name: value for name, value in checks.items() if value}
    if failed:
        raise RefreshFailed(f"validation failed: {failed}")
    log("5/6 PASS: validated " + " ".join(f"{k}=0" for k in checks) +
        f" rows={sum(staged_counts.values())}")


def swap_into_place(target_dsn):
    with psycopg.connect(server_dsn(target_dsn), autocommit=True) as admin:
        drop_database(admin, RETIRED)
        had_target = database_exists(admin, TARGET)
        if had_target:
            try:
                admin.execute(sql.SQL("ALTER DATABASE {} RENAME TO {}").format(
                    sql.Identifier(TARGET), sql.Identifier(RETIRED)))
            except psycopg.errors.ObjectInUse:
                raise RefreshFailed("pseudo-prod has active connections; close them and rerun (nothing was replaced)")
        admin.execute(sql.SQL("ALTER DATABASE {} RENAME TO {}").format(sql.Identifier(STAGING), sql.Identifier(TARGET)))
        if had_target:
            drop_database(admin, RETIRED)
    log("6/6 PASS: pseudo-prod replaced with the new pseudonymised clone")


def cleanup_staging(target_dsn):
    try:
        with psycopg.connect(server_dsn(target_dsn), autocommit=True) as admin:
            drop_database(admin, STAGING)
    except psycopg.Error:
        pass


def refresh(env=os.environ):
    source_admin = env["SOURCE_ADMIN_DSN"]
    source = env["SOURCE_DSN"]
    target = env["PSEUDO_PROD_DSN"]
    key = tok.load_or_create_key()
    check_schema(source_admin)
    try:
        clone_to_staging(source_admin, target)
        staging = dsn_for(target, STAGING)
        tokenize_staging(source, staging, key)
        mask_staging(staging)
        validate_staging(source, staging, key)
        swap_into_place(target)
    except Exception:
        cleanup_staging(target)
        raise


def main():
    try:
        refresh()
    except RefreshStopped as stop:
        print("STOP: production's schema differs from the pseudo-prod schema defined in code:")
        print(stop)
        print(f"No data was copied and pseudo-prod was not changed. Details: {ARTIFACTS / 'schema.diff'}")
        print("Add pseudonymisation rules for new columns in pseudo_prod_schema.py, or revert the schema change.")
        return 2
    except (RefreshFailed, tok.TokenizationError, psycopg.Error) as err:
        print(f"FAIL: {err}. pseudo-prod was not changed.")
        return 1
    print("PASS: pseudo-prod refreshed, pseudonymised and verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
