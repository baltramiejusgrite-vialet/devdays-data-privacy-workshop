"""Read-only database gateway: the only path from agent_net to PostgreSQL on db_net.

Logs in as lab_gateway. Every request except /health needs "Authorization: Bearer <token>".
Identity and permissions come only from the database's verified token-to-company binding
(lab_api.authenticate / lab_api.salary_summary). Identity headers such as X-Company-ID,
X-User or X-Role are ignored. Individual salary rows are never available.
"""

import json
import re
import sys
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg

CONFIG = json.loads(Path("/run/gateway/connection.json").read_text())


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def query(sql, params=()):
    with psycopg.connect(**CONFIG, connect_timeout=5) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute(sql, params)
            columns = [col.name for col in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


def bearer_token(headers):
    scheme, _, token = (headers.get("Authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HttpError(401, "authentication required")
    return token.strip()


def authenticate(token):
    rows = query("SELECT actor, company_id FROM lab_api.authenticate(%s)", (token,))
    if not rows:
        raise HttpError(401, "invalid or expired token")
    return rows[0]


def health(token):
    return {"status": "ok", "database": query("SELECT 1 AS up")[0]["up"] == 1}


def me(token):
    return authenticate(token)


def projects(token):
    authenticate(token)
    return {"items": query("SELECT project_id, title FROM lab_public.projects ORDER BY project_id")}


def salary_summary(token, company_id):
    try:
        row = query(
            "SELECT company_id, employee_count, average_salary_eur FROM lab_api.salary_summary(%s, %s)",
            (token, int(company_id)),
        )[0]
    except psycopg.errors.InvalidAuthorizationSpecification:
        raise HttpError(401, "invalid or expired token")
    except psycopg.errors.InsufficientPrivilege:
        raise HttpError(403, "token is not valid for this company")
    if row["employee_count"] == 0:
        raise HttpError(404, "not found")
    return row


def individual_salaries(token, company_id):
    authenticate(token)
    raise HttpError(403, "individual salaries are not available")


# (pattern, handler, needs_token)
ROUTES = [
    (re.compile(r"/health"), health, False),
    (re.compile(r"/me"), me, True),
    (re.compile(r"/projects"), projects, True),
    (re.compile(r"/companies/(\d{1,9})/salary-summary"), salary_summary, True),
    (re.compile(r"/companies/(\d{1,9})/salaries(?:/.*)?"), individual_salaries, True),
]


def to_json(value):
    return str(value) if isinstance(value, Decimal) else value


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        for pattern, handler, needs_token in ROUTES:
            match = pattern.fullmatch(self.path)
            if match:
                break
        else:
            return self.reply(404, {"error": "not found"})
        try:
            token = bearer_token(self.headers) if needs_token else None
            return self.reply(200, handler(token, *match.groups()))
        except HttpError as err:
            return self.reply(err.status, {"error": err.message})
        except psycopg.Error as exc:
            return self.reply(503, {"error": type(exc).__name__})

    def reject(self):
        self.reply(405, {"error": "read-only gateway"})

    do_POST = do_PUT = do_PATCH = do_DELETE = reject

    def reply(self, status, payload):
        body = json.dumps(payload, default=to_json).encode()
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Logs method, path and status only; never headers or tokens.
        sys.stderr.write(f"gateway {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
