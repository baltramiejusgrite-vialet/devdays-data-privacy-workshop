import psycopg
import pytest

COMPANY_IDS = "SELECT company_id FROM private_db.company ORDER BY company_id"


def set_company(conn, value):
    conn.execute("SELECT set_config('app.company_id', %s, false)", (value,))


def visible_ids(conn):
    return [row[0] for row in conn.execute(COMPANY_IDS).fetchall()]


def test_row_security_is_enabled(readonly_conn):
    enabled = readonly_conn.execute(
        "SELECT relrowsecurity FROM pg_class WHERE oid = 'private_db.company'::regclass"
    ).fetchone()[0]
    assert enabled is True


def test_no_company_set_shows_no_rows(readonly_conn):
    assert visible_ids(readonly_conn) == []


def test_empty_company_shows_no_rows(readonly_conn):
    set_company(readonly_conn, "")
    assert visible_ids(readonly_conn) == []


@pytest.mark.parametrize("company_id", [1, 600, 1200])
def test_one_company_set_shows_only_that_company(readonly_conn, company_id):
    set_company(readonly_conn, str(company_id))
    assert visible_ids(readonly_conn) == [company_id]


def test_several_companies_set_shows_only_those(readonly_conn):
    set_company(readonly_conn, "7,42,1199")
    assert visible_ids(readonly_conn) == [7, 42, 1199]


def test_unknown_company_shows_no_rows(readonly_conn):
    set_company(readonly_conn, "999999")
    assert visible_ids(readonly_conn) == []


def test_filter_cannot_widen_access(readonly_conn):
    set_company(readonly_conn, "42")
    rows = readonly_conn.execute(
        "SELECT company_id FROM private_db.company WHERE company_id <> 42 OR true"
    ).fetchall()
    assert rows == [(42,)]


def test_count_reflects_only_visible_rows(readonly_conn):
    set_company(readonly_conn, "42")
    assert readonly_conn.execute("SELECT count(*) FROM private_db.company").fetchone()[0] == 1


def test_non_numeric_company_is_rejected(readonly_conn):
    set_company(readonly_conn, "abc")
    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        visible_ids(readonly_conn)


def test_salaries_table_still_denied_with_company_set(readonly_conn):
    set_company(readonly_conn, "42")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        readonly_conn.execute("SELECT salary_eur FROM private_db.employment_contract LIMIT 1").fetchall()


def test_cannot_change_company_rows(readonly_conn):
    set_company(readonly_conn, "42")
    with pytest.raises((psycopg.errors.ReadOnlySqlTransaction, psycopg.errors.InsufficientPrivilege)):
        readonly_conn.execute("UPDATE private_db.company SET employee_count = 1 WHERE company_id = 42")
