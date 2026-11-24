"""Exercise 4, step 1: write a reproducible description of a database schema.

Usage (from schema-refresh-workshop):
    docker compose run --rm refresh-runner python describe_schema.py
    docker compose run --rm refresh-runner python describe_schema.py --dsn-env SOURCE_DSN --output original.schema.txt

Lists every non-system table with its columns and types. Schemas, tables and columns
are sorted alphabetically, so the same schema always produces byte-for-byte the same file.
Only structure is read; no row values.
"""

import argparse
import os
from pathlib import Path

import psycopg

SYSTEM_SCHEMAS = ("pg_catalog", "information_schema")


def read_schema(conn):
    """{"schema.table": [(column, type), ...]} sorted alphabetically."""
    rows = conn.execute(
        "SELECT c.table_schema, c.table_name, c.column_name, "
        "       format_type(a.atttypid, a.atttypmod) AS column_type, c.is_nullable "
        "FROM information_schema.columns c "
        "JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
        "JOIN pg_attribute a ON a.attrelid = format('%%I.%%I', c.table_schema, c.table_name)::regclass "
        "                   AND a.attname = c.column_name "
        "WHERE t.table_type = 'BASE TABLE' AND c.table_schema <> ALL(%s) AND c.table_schema NOT LIKE 'pg_toast%%' "
        "ORDER BY 1, 2, 3",
        (list(SYSTEM_SCHEMAS),),
    ).fetchall()
    schema = {}
    for table_schema, table, column, column_type, nullable in rows:
        suffix = "" if nullable == "YES" else " not null"
        schema.setdefault(f"{table_schema}.{table}", []).append((column, column_type + suffix))
    return {table: sorted(columns) for table, columns in sorted(schema.items())}


def render_schema(schema):
    lines = []
    for table, columns in schema.items():
        lines.append(f"table {table}")
        lines.extend(f"  {column}: {column_type}" for column, column_type in columns)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dsn-env", default="PSEUDO_PROD_DSN", help="environment variable holding the DSN")
    parser.add_argument("--output", default="pseudo-prod.schema.txt")
    args = parser.parse_args()
    with psycopg.connect(os.environ[args.dsn_env], autocommit=True) as conn:
        text = render_schema(read_schema(conn))
    Path(args.output).write_text(text, encoding="utf-8")
    print(f"Wrote {args.output}: {text.count('table ')} tables, {text.count(': ')} columns")


if __name__ == "__main__":
    main()
