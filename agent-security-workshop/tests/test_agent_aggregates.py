"""Step 6 aggregate checks, run from the host. Safe to run repeatedly; only reads.

Pass: average results are returned; every way of getting individual salaries fails,
both over the gateway HTTP API and directly with the gateway's own database login.
No individual salary value is ever printed.
Requires the lab to be running: docker compose up -d --wait (from agent-security-workshop).
"""

import json
import subprocess
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
EXPECTED_SUMMARIES = {
    1: {"company_id": 1, "employee_count": 3, "average_salary_eur": "4000.00"},
    2: {"company_id": 2, "employee_count": 3, "average_salary_eur": "7666.33"},
    3: {"company_id": 3, "employee_count": 1, "average_salary_eur": "8000.00"},
}


def run(*args):
    return subprocess.run(
        args, cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60
    )


def exec_python(service, code):
    return run("docker", "compose", "exec", "-T", service, "python", "-c", code).stdout.strip()


def gateway_get(path):
    """GET from the agent container; returns (status, json body)."""
    code = (
        "import json, os, urllib.request as u, urllib.error as e\n"
        "try:\n"
        f"    r = u.urlopen(os.environ['GATEWAY_URL'] + {path!r}, timeout=10)\n"
        "    print(json.dumps([r.status, json.load(r)]))\n"
        "except e.HTTPError as err:\n"
        "    print(json.dumps([err.code, json.load(err)]))"
    )
    status, body = json.loads(exec_python("agent", code))
    return status, body


def db_as_gateway(sql):
    """Run SQL with the gateway's real login; returns 'ok', or the error class name."""
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "try:\n"
        "    with psycopg.connect(**cfg, autocommit=True) as db:\n"
        f"        db.execute({sql!r}).fetchall()\n"
        "    print('ok')\n"
        "except psycopg.Error as err:\n"
        "    print(type(err).__name__)"
    )
    return exec_python("gateway", code)


# Averages succeed


@pytest.mark.parametrize("company_id", sorted(EXPECTED_SUMMARIES))
def test_salary_summary_returns_average(company_id):
    status, body = gateway_get(f"/companies/{company_id}/salary-summary")
    assert status == 200
    assert body == EXPECTED_SUMMARIES[company_id]


def test_summary_has_only_aggregate_fields():
    _, body = gateway_get("/companies/1/salary-summary")
    assert set(body) == {"company_id", "employee_count", "average_salary_eur"}


def test_summary_for_unknown_company_is_not_found():
    status, _ = gateway_get("/companies/999/salary-summary")
    assert status == 404


def test_aggregate_function_succeeds_with_gateway_login():
    assert db_as_gateway("SELECT * FROM lab_api.company_salary_summary(1)") == "ok"


# Individual salaries fail


@pytest.mark.parametrize("path", ["/companies/1/salaries", "/companies/2/salaries", "/companies/1/salaries/101"])
def test_individual_salary_request_forbidden(path):
    status, body = gateway_get(path)
    assert status == 403
    assert "salary_eur" not in json.dumps(body)


@pytest.mark.parametrize("path", ["/salaries", "/employees", "/companies/1/employees", "/companies/1"])
def test_other_salary_paths_not_available(path):
    status, _ = gateway_get(path)
    assert status == 404


def test_row_function_execute_denied():
    assert db_as_gateway("SELECT * FROM lab_api.salary_rows(1)") == "InsufficientPrivilege"


def test_salary_table_select_denied():
    assert db_as_gateway("SELECT salary_eur FROM lab_private.employee_salaries") == "InsufficientPrivilege"


@pytest.mark.parametrize("role", ["lab_admin", "layer_row_reader"])
def test_cannot_switch_to_privileged_role(role):
    assert db_as_gateway(f"SET ROLE {role}") == "InsufficientPrivilege"


def test_gateway_login_is_not_admin():
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "with psycopg.connect(**cfg) as db:\n"
        "    print(db.execute('SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user').fetchone())"
    )
    assert exec_python("gateway", code) == "('lab_gateway', False)"


def test_gateway_can_execute_only_the_aggregate():
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "with psycopg.connect(**cfg) as db:\n"
        "    rows = db.execute(\"SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \"\n"
        "                      \"WHERE n.nspname = 'lab_api' AND has_function_privilege(p.oid, 'EXECUTE') ORDER BY 1\").fetchall()\n"
        "    print([r[0] for r in rows])"
    )
    assert exec_python("gateway", code) == "['company_salary_summary']"


# Public projects still available


def test_public_projects_still_readable():
    status, body = gateway_get("/projects")
    assert status == 200
    assert [p["title"] for p in body["items"]] == ["Conference schedule", "Workshop materials"]
