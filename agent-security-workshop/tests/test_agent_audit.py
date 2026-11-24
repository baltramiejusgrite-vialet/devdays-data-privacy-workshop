"""Step 8 audit checks against the running lab. Safe to run repeatedly.

Pass: every gateway query and access decision is logged in lab_audit.events with the
request ID the caller received; the gateway can only INSERT audit rows; and if auditing
fails the caller gets 503 with no data. Audit rows are read as the trusted lab_admin.
"""

import subprocess
import uuid

import pytest
from gateway_client import LAB_DIR, admin_sql, gateway_request_with_id

FORGED = {"X-Company-ID": "2", "X-User": "administrator", "X-Role": "admin"}
COLUMNS = "actor, action, company_id, method, path, query, status, outcome"


def audit_row(request_id):
    rows = admin_sql(f"SELECT {COLUMNS} FROM lab_audit.events WHERE request_id = '{uuid.UUID(request_id)}'")
    assert len(rows) == 1, f"expected exactly one audit row for {request_id}, found {len(rows)}"
    return rows[0]


# Every query and access decision is logged


@pytest.mark.parametrize("path,token,expected", [
    ("/me", "agent", ["workshop-agent", "identity", "1", "GET", "/me", "lab_api.authenticate(<token>)", "200", "allowed"]),
    ("/projects", "agent", ["workshop-agent", "projects", "1", "GET", "/projects",
                            "SELECT project_id, title FROM lab_public.projects ORDER BY project_id", "200", "allowed"]),
    ("/companies/1/salary-summary", "agent", ["workshop-agent", "salary_summary", "1", "GET", "/companies/1/salary-summary",
                                              "lab_api.salary_summary(<token>, 1)", "200", "allowed"]),
    ("/companies/2/salary-summary", "agent", ["workshop-agent", "salary_summary", "2", "GET", "/companies/2/salary-summary",
                                              "lab_api.salary_summary(<token>, 2)", "403", "denied"]),
    ("/companies/1/salaries", "agent", ["workshop-agent", "individual_salaries", "1", "GET", "/companies/1/salaries",
                                        "", "403", "denied"]),
    ("/companies/1/salary-summary", None, ["", "salary_summary", "", "GET", "/companies/1/salary-summary", "", "401", "denied"]),
    ("/companies/1/salary-summary", "tampered", ["", "salary_summary", "", "GET", "/companies/1/salary-summary", "", "401", "denied"]),
    ("/does-not-exist", "agent", ["", "unknown_path", "", "GET", "/does-not-exist", "", "404", "denied"]),
])
def test_request_is_audited(path, token, expected):
    kwargs = {"token": None} if token is None else {"tamper": token == "tampered"}
    status, _, request_id = gateway_request_with_id(path, **kwargs)
    assert str(status) == expected[6]
    assert audit_row(request_id) == expected


def test_write_attempt_is_audited():
    status, _, request_id = gateway_request_with_id("/projects", method="POST")
    assert status == 405
    assert audit_row(request_id) == ["", "write_attempt", "", "POST", "/projects", "", "405", "denied"]


def test_forged_headers_logged_as_verified_identity():
    status, _, request_id = gateway_request_with_id("/companies/2/salary-summary", headers=FORGED)
    assert status == 403
    actor, action, company_id, *_ , outcome = audit_row(request_id)
    assert (actor, action, company_id, outcome) == ("workshop-agent", "salary_summary", "2", "denied")


def test_every_response_has_a_request_id():
    for path in ["/me", "/companies/2/salary-summary", "/nope"]:
        _, _, request_id = gateway_request_with_id(path)
        assert uuid.UUID(request_id)


def test_health_checks_not_audited():
    _, _, request_id = gateway_request_with_id("/health", token=None)
    assert admin_sql(f"SELECT count(*) FROM lab_audit.events WHERE request_id = '{uuid.UUID(request_id)}'") == [["0"]]


def test_audit_rows_hold_no_tokens_or_salaries():
    leaked = admin_sql(
        "SELECT count(*) FROM lab_audit.events e "
        "WHERE EXISTS (SELECT 1 FROM lab_private.access_tokens t "
        "              WHERE position(encode(t.token_sha256, 'hex') IN e::text) > 0) "
        "   OR e::text ~ 'Bearer|average_salary_eur|salary_eur'"
    )
    assert leaked == [["0"]]


# Append-only: the gateway may INSERT, never UPDATE, DELETE or read


@pytest.mark.parametrize("privilege,expected", [("INSERT", "t"), ("UPDATE", "f"), ("DELETE", "f"),
                                                ("SELECT", "f"), ("TRUNCATE", "f")])
def test_gateway_audit_privileges(privilege, expected):
    sql = f"SELECT has_table_privilege('gateway_reader', 'lab_audit.events', '{privilege}')"
    assert admin_sql(sql) == [[expected]]


@pytest.mark.parametrize("sql", ["UPDATE lab_audit.events SET outcome = 'allowed'", "DELETE FROM lab_audit.events",
                                 "TRUNCATE lab_audit.events", "SELECT * FROM lab_audit.events"])
def test_gateway_cannot_change_or_read_audit(sql):
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "try:\n"
        "    with psycopg.connect(**cfg) as c:\n"
        f"        c.execute({sql!r})\n"
        "    print('allowed')\n"
        "except psycopg.errors.InsufficientPrivilege:\n"
        "    print('refused')"
    )
    result = subprocess.run(["docker", "compose", "exec", "-T", "gateway", "python", "-c", code], cwd=LAB_DIR,
                            capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60)
    assert result.stdout.strip() == "refused"


# Audit failure: no data leaves the gateway (permission restored in finally)


def test_audit_failure_withholds_data():
    admin_sql("REVOKE INSERT ON lab_audit.events FROM gateway_reader")
    try:
        status, body, request_id = gateway_request_with_id("/companies/1/salary-summary")
    finally:
        admin_sql("GRANT INSERT ON lab_audit.events TO gateway_reader")
    assert status == 503
    assert set(body) == {"error", "request_id"}
    assert body["request_id"] == request_id
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "--since", "2m", "gateway"], cwd=LAB_DIR,
                          capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60).stdout
    assert f"gateway audit failure request_id={request_id}; no data returned" in logs


def test_audit_restored_after_failure_test():
    status, _, request_id = gateway_request_with_id("/companies/1/salary-summary")
    assert status == 200
    assert audit_row(request_id)[-1] == "allowed"
