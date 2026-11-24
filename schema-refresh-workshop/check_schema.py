"""Stop the clone when production has columns the pseudo-prod code does not handle.

Usage: docker compose run --rm refresh-runner python check_schema.py
Compares the live production schema (SOURCE_DSN) with pseudo_prod_schema.py.
Exit 0 when they match; exit 2 with an informative message when they do not.
"""

import os
import sys

import psycopg

from pseudo_prod_schema import business_schema, schema_differences


def check(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn:
        return schema_differences(business_schema(conn))


def main():
    problems = check(os.environ["SOURCE_DSN"])
    if problems:
        print("STOP: the production schema does not match the pseudo-prod schema defined in code.")
        for problem in problems:
            print(f"  - {problem}")
        print("Cloning stopped. Add a rule for each change in pseudo_prod_schema.py, or revert the change.")
        return 2
    print("PASS: production schema matches the pseudo-prod schema defined in code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
