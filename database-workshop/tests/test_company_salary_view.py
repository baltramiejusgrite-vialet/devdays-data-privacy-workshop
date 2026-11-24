from decimal import Decimal

import psycopg
import pytest

VIEW = "private_db.my_company_average_salary"

# Averages from the generated fixtures, computed by the workshop admin user.
EXPECTED_AVERAGES = {
    1: Decimal("51686.02"),
    600: Decimal("54754.05"),
    1200: Decimal("53241.48"),
}


def set_company(conn, value):
    conn.execute("SELECT set_config('app.company_id', %s, false)", (value,))


def test_connects_as_readonly_user(readonly_conn):
    assert readonly_conn.execute("SELECT current_user").fetchone()[0] == "workshop_readonly"


def test_view_requires_company_id(readonly_conn):
    with pytest.raises(psycopg.errors.UndefinedObject):
        readonly_conn.execute(f"SELECT * FROM {VIEW}").fetchall()


def test_view_rejects_empty_company_id(readonly_conn):
    set_company(readonly_conn, "")
    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        readonly_conn.execute(f"SELECT * FROM {VIEW}").fetchall()


@pytest.mark.parametrize("company_id", sorted(EXPECTED_AVERAGES))
def test_view_returns_only_that_company(readonly_conn, company_id):
    set_company(readonly_conn, str(company_id))
    rows = readonly_conn.execute(f"SELECT company_id, average_salary_eur FROM {VIEW}").fetchall()
    assert rows == [(company_id, EXPECTED_AVERAGES[company_id])]


def test_view_returns_nothing_for_unknown_company(readonly_conn):
    set_company(readonly_conn, "999999")
    assert readonly_conn.execute(f"SELECT * FROM {VIEW}").fetchall() == []


@pytest.mark.parametrize(
    "table",
    [
        "private_db.employment_contract",
        "private_db.payroll_event",
        "private_db.person_identity",
    ],
)
def test_private_tables_are_denied(readonly_conn, table):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        readonly_conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()


def test_public_schema_is_denied(readonly_conn):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        readonly_conn.execute("SELECT 1 FROM public_db.company_registry LIMIT 1").fetchall()


def test_only_the_view_and_company_table_are_granted(readonly_conn):
    grants = readonly_conn.execute(
        "SELECT table_schema || '.' || table_name FROM information_schema.role_table_grants "
        "WHERE grantee = current_user ORDER BY 1"
    ).fetchall()
    assert grants == [("private_db.company",), (VIEW,)]


def test_readonly_user_cannot_write(readonly_conn):
    with pytest.raises((psycopg.errors.ReadOnlySqlTransaction, psycopg.errors.InsufficientPrivilege)):
        readonly_conn.execute("UPDATE private_db.company SET employee_count = 1 WHERE company_id = 1")
