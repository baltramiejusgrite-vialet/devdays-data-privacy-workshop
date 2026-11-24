"""Step 7 identity checks, run from the host. Safe to run repeatedly; only reads.

Pass: own-company access works with the agent's token; anonymous, tampered, invalid
and cross-company access are blocked; identity headers never grant anything.
Tokens are read inside the containers and never printed.
"""

import json
import subprocess
from pathlib import Path

import pytest
from gateway_client import AGENT_TOKEN, gateway_request

LAB_DIR = Path(__file__).resolve().parent.parent
FORGED = {"X-Company-ID": "2", "X-User": "administrator", "X-Role": "admin"}
PROTECTED = ["/me", "/projects", "/companies/1/salary-summary", "/companies/2/salary-summary", "/companies/1/salaries"]


def db_as_gateway(sql):
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "try:\n"
        "    with psycopg.connect(**cfg, autocommit=True) as db:\n"
        f"        print(db.execute({sql!r}).fetchall())\n"
        "except psycopg.Error as err:\n"
        "    print(type(err).__name__)"
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "gateway", "python", "-c", code],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    return result.stdout.strip()


# Own-company access works


def test_me_returns_verified_identity():
    assert gateway_request("/me") == (200, {"actor": "workshop-agent", "company_id": 1})


def test_own_company_summary_available():
    status, body = gateway_request("/companies/1/salary-summary")
    assert status == 200
    assert body["company_id"] == 1


def test_projects_available_with_token():
    status, _ = gateway_request("/projects")
    assert status == 200


# Anonymous access is blocked


@pytest.mark.parametrize("path", PROTECTED)
def test_no_token_is_unauthorized(path):
    status, _ = gateway_request(path, token=None)
    assert status == 401


@pytest.mark.parametrize("credential", ["", "invalid-token", "Bearer", "null", "' OR '1'='1"])
def test_invalid_token_is_unauthorized(credential):
    status, _ = gateway_request("/companies/1/salary-summary", token=credential)
    assert status == 401


@pytest.mark.parametrize("path", ["/me", "/companies/1/salary-summary", "/projects"])
def test_tampered_token_is_unauthorized(path):
    status, _ = gateway_request(path, tamper=True)
    assert status == 401


def test_health_needs_no_token():
    status, body = gateway_request("/health", token=None)
    assert (status, body["status"]) == (200, "ok")


# Cross-company access is blocked


@pytest.mark.parametrize("company_id", [2, 3])
def test_other_company_forbidden(company_id):
    status, _ = gateway_request(f"/companies/{company_id}/salary-summary")
    assert status == 403


# Identity headers grant nothing


def test_forged_headers_do_not_change_identity():
    assert gateway_request("/me", headers=FORGED) == (200, {"actor": "workshop-agent", "company_id": 1})


def test_forged_headers_do_not_unlock_other_company():
    status, _ = gateway_request("/companies/2/salary-summary", headers=FORGED)
    assert status == 403


@pytest.mark.parametrize("path", ["/me", "/companies/2/salary-summary", "/projects"])
def test_forged_headers_without_token_unauthorized(path):
    status, _ = gateway_request(path, token=None, headers=FORGED)
    assert status == 401


# The database enforces the binding, not only the gateway


def test_db_salary_summary_rejects_invalid_token():
    assert db_as_gateway("SELECT * FROM lab_api.salary_summary('invalid-token', 1)") == "InvalidAuthorizationSpecification"


def test_db_authenticate_unknown_token_returns_nothing():
    assert db_as_gateway("SELECT * FROM lab_api.authenticate('invalid-token')") == "[]"


def test_tokens_stored_only_as_hashes():
    code = (
        "import json, psycopg\n"
        "token = json.load(open('/run/identity/access.json'))['gateway_token']\n"
        "with psycopg.connect('postgresql://lab_admin:student-demo@db:5432/agent_lab') as db:\n"
        "    rows = db.execute('SELECT token_sha256, actor, company_id FROM lab_private.access_tokens').fetchall()\n"
        "print(any(token.encode() in bytes(r[0]) for r in rows), [(r[1], r[2], len(r[0])) for r in rows])"
    )
    result = subprocess.run(
        ["docker", "compose", "--profile", "setup", "run", "--rm", "-T", "--no-deps", "--entrypoint", "python",
         "identity-issuer", "-c", code],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=120,
    )
    assert result.stdout.strip().splitlines()[-1] == "False [('workshop-agent', 1, 32)]"


def test_agent_token_file_is_read_only():
    code = (
        "import os\n"
        "try:\n"
        "    open('/run/identity/access.json', 'a').close(); print('writable')\n"
        "except OSError:\n"
        "    print('read-only')"
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "agent", "python", "-c", code],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    assert result.stdout.strip() == "read-only"
