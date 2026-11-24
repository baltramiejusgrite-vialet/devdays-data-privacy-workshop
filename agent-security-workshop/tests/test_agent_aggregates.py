"""Step 6 aggregate checks (with step 7 identity), run from the host. Safe to run repeatedly.

Pass: the agent's own company average is returned; individual salaries fail over the
gateway HTTP API and with the gateway's own database login. No salary or token is printed.
Requires the lab to be running: docker compose up -d --wait (from agent-security-workshop).
"""

import json
import subprocess
from pathlib import Path

import pytest
from gateway_client import gateway_request

LAB_DIR = Path(__file__).resolve().parent.parent
OWN_SUMMARY = {"company_id": 1, "employee_count": 3, "average_salary_eur": "4000.00"}


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
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "gateway", "python", "-c", code],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    return result.stdout.strip()


# Averages succeed (for the agent's own company)


def test_own_company_summary_returns_average():
    assert gateway_request("/companies/1/salary-summary") == (200, OWN_SUMMARY)


def test_summary_has_only_aggregate_fields():
    _, body = gateway_request("/companies/1/salary-summary")
    assert set(body) == {"company_id", "employee_count", "average_salary_eur"}


@pytest.mark.parametrize("company_id", [2, 3, 999])
def test_other_company_summary_forbidden(company_id):
    status, body = gateway_request(f"/companies/{company_id}/salary-summary")
    assert status == 403
    assert "average_salary_eur" not in body


# Individual salaries fail


@pytest.mark.parametrize("path", ["/companies/1/salaries", "/companies/2/salaries", "/companies/1/salaries/101"])
def test_individual_salary_request_forbidden(path):
    status, body = gateway_request(path)
    assert status == 403
    assert "salary_eur" not in json.dumps(body)


@pytest.mark.parametrize("path", ["/salaries", "/employees", "/companies/1/employees", "/companies/1"])
def test_other_salary_paths_not_available(path):
    status, _ = gateway_request(path)
    assert status == 404


def test_row_function_execute_denied():
    assert db_as_gateway("SELECT * FROM lab_api.salary_rows(1)") == "InsufficientPrivilege"


def test_open_summary_function_execute_denied():
    assert db_as_gateway("SELECT * FROM lab_api.company_salary_summary(1)") == "InsufficientPrivilege"


@pytest.mark.parametrize("table", ["lab_private.employee_salaries", "lab_private.access_tokens"])
def test_private_table_select_denied(table):
    assert db_as_gateway(f"SELECT * FROM {table}") == "InsufficientPrivilege"


@pytest.mark.parametrize("role", ["lab_admin", "layer_row_reader"])
def test_cannot_switch_to_privileged_role(role):
    assert db_as_gateway(f"SET ROLE {role}") == "InsufficientPrivilege"


def test_gateway_login_is_not_admin():
    code = "SELECT 1 FROM pg_roles WHERE rolname = current_user AND current_user = 'lab_gateway' AND NOT rolsuper HAVING count(*) = 1"
    assert db_as_gateway(code) == "ok"


def test_gateway_can_execute_only_token_functions():
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "with psycopg.connect(**cfg) as db:\n"
        "    rows = db.execute(\"SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \"\n"
        "                      \"WHERE n.nspname = 'lab_api' AND has_function_privilege(p.oid, 'EXECUTE') ORDER BY 1\").fetchall()\n"
        "    print([r[0] for r in rows])"
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "gateway", "python", "-c", code],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    assert result.stdout.strip() == "['authenticate', 'salary_summary']"


# Public projects still available


def test_public_projects_still_readable():
    status, body = gateway_request("/projects")
    assert status == 200
    assert [p["title"] for p in body["items"]] == ["Conference schedule", "Workshop materials"]
