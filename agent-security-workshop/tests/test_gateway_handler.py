"""Step 8 handler tests: run the gateway's request logic against a fake database connection.

No containers needed. Verifies that the audit row is inserted and committed before any
data is returned, and that data is withheld if the insert or the commit fails.
"""

import importlib.util
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")

APP = Path(__file__).resolve().parent.parent / "gateway" / "app.py"
spec = importlib.util.spec_from_file_location("gateway_app", APP)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)

SUMMARY = {"company_id": 1, "employee_count": 3, "average_salary_eur": "4000.00"}


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = []
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        self.conn.events.append(("query", sql))
        if "lab_api.authenticate" in sql:
            self.rows = [("workshop-agent", 1)] if params[0] == "good" else []
            self.description = [type("C", (), {"name": n}) for n in ("actor", "company_id")]
        elif "lab_api.salary_summary" in sql:
            if params[1] != 1:
                raise psycopg.errors.InsufficientPrivilege("other company")
            self.rows = [tuple(SUMMARY.values())]
            self.description = [type("C", (), {"name": n}) for n in SUMMARY]

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, fail_insert=False, fail_commit=False):
        self.events = []
        self.fail_insert = fail_insert
        self.fail_commit = fail_commit

    def cursor(self):
        return FakeCursor(self)

    def execute(self, sql, params=()):
        if sql == gateway.AUDIT_SQL:
            if self.fail_insert:
                raise psycopg.errors.InsufficientPrivilege("permission denied for table events")
            self.events.append(("audit", params))
        else:
            self.events.append(("execute", sql))

    def commit(self):
        if self.fail_commit:
            raise psycopg.OperationalError("connection lost during commit")
        self.events.append(("commit", None))

    def rollback(self):
        self.events.append(("rollback", None))

    def close(self):
        self.events.append(("close", None))


def run(path, token="good", **conn_options):
    conn = FakeConnection(**conn_options)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, payload = gateway.process("GET", path, headers, "req-1", connect=lambda: conn)
    return status, payload, [kind for kind, _ in conn.events], conn


def test_audit_inserted_then_committed_before_data_returned():
    status, payload, kinds, _ = run("/companies/1/salary-summary")
    assert (status, payload) == (200, SUMMARY)
    assert kinds[-3:] == ["audit", "commit", "close"]
    assert kinds.index("query") < kinds.index("audit") < kinds.index("commit")


def test_commit_failure_withholds_data():
    status, payload, kinds, _ = run("/companies/1/salary-summary", fail_commit=True)
    assert status == 503
    assert payload == {**gateway.AUDIT_FAILED, "request_id": "req-1"}
    assert "average_salary_eur" not in payload
    assert "commit" not in kinds


def test_insert_failure_withholds_data():
    status, payload, kinds, _ = run("/companies/1/salary-summary", fail_insert=True)
    assert status == 503
    assert "average_salary_eur" not in payload
    assert "commit" not in kinds


def test_connection_failure_withholds_data():
    def broken():
        raise psycopg.OperationalError("database unreachable")
    status, payload = gateway.process("GET", "/me", {"Authorization": "Bearer good"}, "req-2", connect=broken)
    assert (status, payload) == (503, {**gateway.AUDIT_FAILED, "request_id": "req-2"})


def test_denied_request_still_audited_and_committed():
    status, _, kinds, conn = run("/companies/2/salary-summary")
    assert status == 403
    audit = next(params for kind, params in conn.events if kind == "audit")
    assert audit[2:] == ("salary_summary", 2, "GET", "/companies/2/salary-summary",
                         "lab_api.salary_summary(<token>, 2)", 403, "denied")
    assert kinds[-2:] == ["commit", "close"]


def test_anonymous_request_audited_without_actor():
    status, _, _, conn = run("/me", token=None)
    assert status == 401
    audit = next(params for kind, params in conn.events if kind == "audit")
    assert audit[1] is None and audit[-2:] == (401, "denied")


def test_audit_row_never_contains_token():
    _, _, _, conn = run("/companies/1/salary-summary", token="good")
    audit = next(params for kind, params in conn.events if kind == "audit")
    assert "good" not in repr(audit)


def test_forged_identity_headers_ignored():
    conn = FakeConnection()
    headers = {"Authorization": "Bearer good", "X-Company-ID": "2", "X-User": "administrator", "X-Role": "admin"}
    status, payload = gateway.process("GET", "/me", headers, "req-3", connect=lambda: conn)
    assert (status, payload) == (200, {"actor": "workshop-agent", "company_id": 1})
