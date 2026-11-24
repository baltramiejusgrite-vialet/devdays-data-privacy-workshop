"""Replace email addresses and national IDs in pseudo-prod with HMAC-SHA256 tokens.

Usage (from schema-refresh-workshop):
    docker compose run --rm refresh-runner python tokenize_pseudo_prod.py tokenize
    docker compose run --rm refresh-runner python tokenize_pseudo_prod.py verify

What is tokenized: every text column in the business schema whose name contains "email"
or "national_id", and string values nested in JSON/JSONB columns under keys with those
names. Columns are discovered from the live schema, so new columns are covered too.

  * Tokens are HMAC-SHA256(key, kind + value). One "kind" per identifier type, so the same
    email gets the same token in every column and the employment -> people join survives.
  * NULLs stay NULL. Re-running with the same key changes nothing.
  * All tables are updated in one transaction. Foreign-key triggers are paused with
    SET LOCAL session_replication_role, which ends with the transaction, so the original
    foreign-key behaviour is restored; dangling links are counted before committing.
  * The production source is only read (SOURCE_DSN, a read-only login).
  * A different key is refused: every target value must equal its raw source value or
    that value's token under the current key.

The 32-byte key lives in /keys (the pseudonym_keys volume), mode 0600. It is never
printed, stored in the database, or written to source control.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path

import psycopg
from psycopg import sql

SCHEMA = "business"
KEY_FILE = Path(os.environ.get("PSEUDONYM_KEY_FILE", "/keys/hmac-sha256.key"))
FIELD_KINDS = [("national_id", re.compile(r"national_?id", re.I)), ("email", re.compile(r"e_?mail", re.I))]


class TokenizationError(Exception):
    pass


# --- key and tokens ---------------------------------------------------------------------


def load_or_create_key(path=KEY_FILE):
    path = Path(path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(32))
    os.chmod(path, 0o600)
    key = path.read_bytes()
    if len(key) != 32:
        raise TokenizationError(f"pseudonym key must be 32 bytes, found {len(key)}")
    return key


def kind_for(name):
    for kind, pattern in FIELD_KINDS:
        if pattern.search(name):
            return kind
    return None


def token(key, kind, value):
    digest = hmac.new(key, f"{kind}\x00{value}".encode(), hashlib.sha256).hexdigest()
    if kind == "email":
        return f"tok-{digest}@pseudonym.invalid"
    return f"NID-{digest}"


def tokenize_json(key, value, kind_of=kind_for):
    """Returns a copy of a JSON value with identifier strings under matching keys tokenized."""
    if isinstance(value, dict):
        out = {}
        for name, item in value.items():
            kind = kind_of(name)
            if kind and isinstance(item, str):
                out[name] = token(key, kind, item)
            else:
                out[name] = tokenize_json(key, item, kind_of)
        return out
    if isinstance(value, list):
        return [tokenize_json(key, item, kind_of) for item in value]
    return value


def json_identifiers(value, kind_of=kind_for):
    """Yields (kind, string) for every identifier string nested in a JSON value."""
    if isinstance(value, dict):
        for name, item in value.items():
            kind = kind_of(name)
            if kind and isinstance(item, str):
                yield kind, item
            else:
                yield from json_identifiers(item, kind_of)
    elif isinstance(value, list):
        for item in value:
            yield from json_identifiers(item, kind_of)


def expected_value(key, kind, data_type, raw):
    if raw is None:
        return None
    if data_type in ("json", "jsonb"):
        return tokenize_json(key, raw)
    return token(key, kind, raw)


# --- schema discovery -------------------------------------------------------------------


def target_columns(conn):
    """[(table, column, kind or None for JSON, data_type)] in the business schema."""
    rows = conn.execute(
        "SELECT table_name, column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = %s AND data_type IN ('text', 'character varying', 'json', 'jsonb') "
        "ORDER BY table_name, ordinal_position",
        (SCHEMA,),
    ).fetchall()
    columns = []
    for table, column, data_type in rows:
        if data_type in ("json", "jsonb"):
            columns.append((table, column, None, data_type))
        elif kind_for(column):
            columns.append((table, column, kind_for(column), data_type))
    return columns


def primary_key(conn, table):
    rows = conn.execute(
        "SELECT a.attname FROM pg_index i "
        "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
        "WHERE i.indrelid = %s::regclass AND i.indisprimary ORDER BY a.attnum",
        (f"{SCHEMA}.{table}",),
    ).fetchall()
    if not rows:
        raise TokenizationError(f"{SCHEMA}.{table} has no primary key; rows cannot be matched to the source")
    return [r[0] for r in rows]


def foreign_keys(conn):
    """[(table, [columns], ref_table, [ref_columns])] inside the business schema."""
    rows = conn.execute(
        "SELECT c.conrelid::regclass::text, c.confrelid::regclass::text, "
        "       array(SELECT attname FROM pg_attribute WHERE attrelid = c.conrelid AND attnum = ANY(c.conkey)), "
        "       array(SELECT attname FROM pg_attribute WHERE attrelid = c.confrelid AND attnum = ANY(c.confkey)) "
        "FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
        "WHERE c.contype = 'f' AND n.nspname = %s",
        (SCHEMA,),
    ).fetchall()
    return [(t.split(".")[-1], list(cols), r.split(".")[-1], list(rcols)) for t, r, cols, rcols in rows]


def fetch_column(conn, table, pk, column):
    query = sql.SQL("SELECT {pk}, {col} FROM {tbl}").format(
        pk=sql.SQL(", ").join(map(sql.Identifier, pk)), col=sql.Identifier(column),
        tbl=sql.Identifier(SCHEMA, table))
    return {tuple(row[:-1]): row[-1] for row in conn.execute(query).fetchall()}


def orphaned_links(conn):
    total = 0
    for table, cols, ref_table, ref_cols in foreign_keys(conn):
        join = sql.SQL(" AND ").join(
            sql.SQL("r.{} = t.{}").format(sql.Identifier(rc), sql.Identifier(c)) for c, rc in zip(cols, ref_cols))
        not_null = sql.SQL(" AND ").join(sql.SQL("t.{} IS NOT NULL").format(sql.Identifier(c)) for c in cols)
        query = sql.SQL("SELECT count(*) FROM {t} t WHERE {nn} AND NOT EXISTS (SELECT 1 FROM {r} r WHERE {j})").format(
            t=sql.Identifier(SCHEMA, table), r=sql.Identifier(SCHEMA, ref_table), nn=not_null, j=join)
        total += conn.execute(query).fetchone()[0]
    return total


# --- tokenize ---------------------------------------------------------------------------


def plan_updates(key, source, target):
    """For each column, {pk: new value} for rows still holding raw values. Raises on unknown values."""
    updates = {}
    for table, column, kind, data_type in target_columns(target):
        pk = primary_key(target, table)
        raw_rows = fetch_column(source, table, pk, column)
        current_rows = fetch_column(target, table, pk, column)
        changes = {}
        for row_key, current in current_rows.items():
            if row_key not in raw_rows:
                raise TokenizationError(f"{table}.{column} row {row_key} is not in the source")
            raw = raw_rows[row_key]
            wanted = expected_value(key, kind, data_type, raw)
            if current == wanted:
                continue
            if current == raw:
                changes[row_key] = wanted
                continue
            raise TokenizationError(
                f"{table}.{column}: a value matches neither the source nor this key's token "
                "(different key, or the data changed). Nothing was updated.")
        if changes:
            updates[(table, column, data_type)] = (pk, changes)
    return updates


def apply_updates(target, updates):
    for (table, column, data_type), (pk, changes) in updates.items():
        where = sql.SQL(" AND ").join(sql.SQL("{} = %s").format(sql.Identifier(c)) for c in pk)
        query = sql.SQL("UPDATE {tbl} SET {col} = %s WHERE {where}").format(
            tbl=sql.Identifier(SCHEMA, table), col=sql.Identifier(column), where=where)
        params = [
            (psycopg.types.json.Jsonb(value) if data_type == "jsonb" else
             psycopg.types.json.Json(value) if data_type == "json" else value, *row_key)
            for row_key, value in changes.items()
        ]
        with target.cursor() as cur:
            cur.executemany(query, params)


def tokenize(source_dsn, target_dsn, key):
    with psycopg.connect(source_dsn) as source, psycopg.connect(target_dsn) as target:
        source.read_only = True
        with target.transaction():
            target.execute("SET LOCAL session_replication_role = replica")
            updates = plan_updates(key, source, target)
            apply_updates(target, updates)
            orphans = orphaned_links(target)
            if orphans:
                raise TokenizationError(f"{orphans} foreign-key links would break; rolled back")
        changed = sum(len(changes) for _, changes in updates.values())
        return {"updated_values": changed, "columns": len(target_columns(target))}


# --- verify -----------------------------------------------------------------------------


def verify(source_dsn, target_dsn, key):
    with psycopg.connect(source_dsn) as source, psycopg.connect(target_dsn) as target:
        source.read_only = True
        target.read_only = True
        non_keyed = checked = 0
        originals = set()
        for table, column, kind, data_type in target_columns(target):
            pk = primary_key(target, table)
            raw_rows = fetch_column(source, table, pk, column)
            for row_key, current in fetch_column(target, table, pk, column).items():
                raw = raw_rows.get(row_key)
                checked += current is not None
                if row_key not in raw_rows or current != expected_value(key, kind, data_type, raw):
                    non_keyed += 1
                if data_type in ("json", "jsonb"):
                    originals.update(v for _, v in json_identifiers(raw))
                elif raw is not None:
                    originals.add(raw)
        remaining = count_remaining_originals(target, originals)
        orphans = orphaned_links(target)
    return {"checked_values": checked, "non_keyed_values": non_keyed,
            "remaining_original_values": remaining, "orphaned_employment_links": orphans}


def count_remaining_originals(target, originals):
    """Counts rows in ANY text or JSON column of the schema that still contain an original value."""
    if not originals:
        return 0
    rows = target.execute(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = %s AND data_type IN ('text', 'character varying', 'json', 'jsonb')",
        (SCHEMA,),
    ).fetchall()
    found = 0
    for table, column in rows:
        query = sql.SQL("SELECT {c}::text FROM {t} WHERE {c} IS NOT NULL").format(
            c=sql.Identifier(column), t=sql.Identifier(SCHEMA, table))
        for (text,) in target.execute(query):
            found += any(original in text for original in originals)
    return found


# --- command line -----------------------------------------------------------------------


def main(argv):
    if len(argv) != 2 or argv[1] not in ("tokenize", "verify"):
        sys.exit("usage: python tokenize_pseudo_prod.py tokenize|verify")
    key = load_or_create_key()
    source, target = os.environ["SOURCE_DSN"], os.environ["PSEUDO_PROD_DSN"]
    try:
        if argv[1] == "tokenize":
            result = tokenize(source, target, key)
            print(f"tokenized: {json.dumps(result)}")
        result = verify(source, target, key)
    except TokenizationError as err:
        sys.exit(f"FAIL: {err}")
    print(" ".join(f"{name}={value}" for name, value in result.items()))
    ok = result["non_keyed_values"] == 0 and result["remaining_original_values"] == 0 \
        and result["orphaned_employment_links"] == 0
    print("PASS: every identifier is keyed and no original value remains" if ok else "FAIL: verification failed")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv)
