"""Exercise 4, step 2: the pseudo-prod schema, defined in code.

Every column of every table is listed with its type and the method that produces its
pseudo-prod value. A production column that is not listed here has no method, so the
clone must stop until someone decides how it should be handled.
"""

import datetime as dt
from dataclasses import dataclass

from describe_schema import read_schema, render_schema


@dataclass(frozen=True)
class Rule:
    method: str            # copy | hmac_email | hmac_national_id | mask
    value: object = None   # fixed value for mask

    def describe(self):
        return f"mask -> {self.value!r}" if self.method == "mask" else self.method


COPY = Rule("copy")                       # keys and non-personal operational values, unchanged
HMAC_EMAIL = Rule("hmac_email")           # tokenize_pseudo_prod.token(key, "email", value)
HMAC_NATIONAL_ID = Rule("hmac_national_id")


def MASK(value):
    return Rule("mask", value)


PSEUDO_PROD_SCHEMA = {
    "business.companies": {
        "annual_profit_eur": ("integer not null", MASK(0)),
        "company_id": ("bigint not null", COPY),
        "company_name": ("text not null", COPY),
    },
    "business.employment": {
        "company_id": ("bigint not null", COPY),
        "contract_id": ("bigint not null", COPY),
        "department": ("text not null", COPY),
        "employee_email": ("text not null", HMAC_EMAIL),
        "salary_eur": ("integer not null", MASK(3500)),
    },
    "business.people": {
        "birth_date": ("date not null", MASK(dt.date(2000, 1, 1))),
        "email": ("text not null", HMAC_EMAIL),
        "first_name": ("text not null", MASK("Person Anonymous")),
        "last_name": ("text not null", MASK("Person Anonymous")),
        "national_id": ("text not null", HMAC_NATIONAL_ID),
        "person_id": ("bigint not null", COPY),
    },
}


def expected_schema():
    """The code-defined schema in describe_schema's format."""
    return {table: sorted((column, spec[0]) for column, spec in columns.items())
            for table, columns in sorted(PSEUDO_PROD_SCHEMA.items())}


def expected_description():
    return render_schema(expected_schema())


def mask_rules():
    """{(table, column): value} for every masked column, for mask_pseudo_prod."""
    return {(table.split(".")[1], column): rule.value
            for table, columns in PSEUDO_PROD_SCHEMA.items()
            for column, (_, rule) in columns.items() if rule.method == "mask"}


def business_schema(conn):
    return {table: columns for table, columns in read_schema(conn).items() if table.startswith("business.")}


def schema_differences(actual):
    """Readable list of how a live schema differs from the code-defined one (empty when equal)."""
    expected = expected_schema()
    problems = []
    for table in sorted(set(expected) | set(actual)):
        if table not in actual:
            problems.append(f"missing table {table}")
            continue
        if table not in expected:
            problems.append(f"unknown table {table}: no pseudonymisation rules defined")
            continue
        want, have = dict(expected[table]), dict(actual[table])
        for column in sorted(set(want) | set(have)):
            if column not in have:
                problems.append(f"missing column {table}.{column}")
            elif column not in want:
                problems.append(f"unknown column {table}.{column} ({have[column]}): no pseudonymisation rule defined")
            elif want[column] != have[column]:
                problems.append(f"type changed {table}.{column}: expected {want[column]}, found {have[column]}")
    return problems
