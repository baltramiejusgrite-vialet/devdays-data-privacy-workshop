"""Shared helper: call the gateway from inside the agent container.

The agent's token is read inside the container from /run/identity/access.json and is
never returned to the host or printed.
"""

import json
import subprocess
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
AGENT_TOKEN = object()


def gateway_request(path, token=AGENT_TOKEN, headers=None, method="GET", tamper=False):
    """Returns (status, json body). token: AGENT_TOKEN, None (no header) or a literal string.

    tamper=True changes one character of the agent's real token before sending it.
    """
    status, body, _ = gateway_request_with_id(path, token, headers, method, tamper)
    return status, body


def gateway_request_with_id(path, token=AGENT_TOKEN, headers=None, method="GET", tamper=False):
    """Like gateway_request, but returns (status, json body, X-Request-ID)."""
    code = (
        "import json, os, urllib.request as u, urllib.error as e\n"
        "token = json.load(open('/run/identity/access.json'))['gateway_token']\n"
        f"literal = {token if isinstance(token, str) or token is None else 0!r}\n"
        f"use_agent = {token is AGENT_TOKEN}\n"
        f"if {tamper}:\n"
        "    token = token[:-1] + ('A' if token[-1] != 'A' else 'B')\n"
        "credential = token if use_agent else literal\n"
        f"headers = {headers or {}!r}\n"
        "if credential is not None:\n"
        "    headers['Authorization'] = 'Bearer ' + credential\n"
        f"data = b'{{}}' if {method!r} != 'GET' else None\n"
        f"req = u.Request(os.environ['GATEWAY_URL'] + {path!r}, headers=headers, data=data, method={method!r})\n"
        "try:\n"
        "    r = u.urlopen(req, timeout=10)\n"
        "    print(json.dumps([r.status, json.load(r), r.headers.get('X-Request-ID')]))\n"
        "except e.HTTPError as err:\n"
        "    print(json.dumps([err.code, json.load(err), err.headers.get('X-Request-ID')]))"
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "agent", "python", "-c", code],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    status, body, request_id = json.loads(result.stdout.strip())
    return status, body, request_id


def admin_sql(sql):
    """Runs SQL as the trusted host administrator (lab_admin) in the db container; returns rows as lists."""
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
         "-U", "lab_admin", "-d", "agent_lab", "-A", "-t", "-F", "\t", "-c", sql],
        cwd=LAB_DIR, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, timeout=60,
    )
    return [line.split("\t") for line in result.stdout.splitlines() if line]
