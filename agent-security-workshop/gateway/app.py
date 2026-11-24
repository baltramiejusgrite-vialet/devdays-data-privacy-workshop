"""Database gateway: the only path from agent_net to PostgreSQL on db_net.

Logs in as gateway_reader. Every request except /health needs "Authorization: Bearer <token>".
Identity and permissions come only from the database's verified token-to-company binding
(lab_api.authenticate / lab_api.salary_summary); X-Company-ID, X-User and X-Role are ignored.

Auditing (step 8): every request except /health writes one lab_audit.events row in the same
transaction as its data query, and that transaction is committed BEFORE any response is sent.
If the audit insert or the commit fails, the caller gets HTTP 503 with no data.
"""

import json
import re
import sys
import uuid
from dataclasses import dataclass
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg

CONFIG_FILE = Path("/run/gateway/connection.json")
AUDIT_SQL = (
    "INSERT INTO lab_audit.events "
    "(request_id, actor, action, company_id, method, path, query, status, outcome) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
AUDIT_FAILED = {"error": "request could not be audited; no data returned"}


@dataclass
class Result:
    status: int
    payload: dict
    action: str
    actor: str | None = None
    company_id: int | None = None
    query: str | None = None

    @property
    def outcome(self):
        if self.status < 400:
            return "allowed"
        return "error" if self.status >= 500 else "denied"


def connect():
    return psycopg.connect(**json.loads(CONFIG_FILE.read_text()), connect_timeout=5)


def fetch_all(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        columns = [col.name for col in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]


def bearer_token(headers):
    scheme, _, token = (headers.get("Authorization") or "").partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


def authenticate(conn, token):
    rows = fetch_all(conn, "SELECT actor, company_id FROM lab_api.authenticate(%s)", (token,))
    return rows[0] if rows else None


def route_me(conn, identity):
    return Result(200, identity, "identity", query="lab_api.authenticate(<token>)")


def route_projects(conn, identity):
    sql = "SELECT project_id, title FROM lab_public.projects ORDER BY project_id"
    return Result(200, {"items": fetch_all(conn, sql)}, "projects", query=sql)


def route_salary_summary(conn, identity, token, company_id):
    company_id = int(company_id)
    query = f"lab_api.salary_summary(<token>, {company_id})"
    base = {"action": "salary_summary", "company_id": company_id, "query": query}
    try:
        row = fetch_all(
            conn,
            "SELECT company_id, employee_count, average_salary_eur FROM lab_api.salary_summary(%s, %s)",
            (token, company_id),
        )[0]
    except psycopg.errors.InvalidAuthorizationSpecification:
        conn.rollback()
        return Result(401, {"error": "invalid or expired token"}, **base)
    except psycopg.errors.InsufficientPrivilege:
        conn.rollback()
        return Result(403, {"error": "token is not valid for this company"}, **base)
    if row["employee_count"] == 0:
        return Result(404, {"error": "not found"}, **base)
    return Result(200, row, **base)


def route_individual_salaries(conn, identity, company_id):
    return Result(403, {"error": "individual salaries are not available"}, "individual_salaries",
                  company_id=int(company_id), query=None)


# (pattern, handler, passes token to handler)
ROUTES = [
    (re.compile(r"/me"), route_me, False),
    (re.compile(r"/projects"), route_projects, False),
    (re.compile(r"/companies/(\d{1,9})/salary-summary"), route_salary_summary, True),
    (re.compile(r"/companies/(\d{1,9})/salaries(?:/.*)?"), route_individual_salaries, False),
]


def resolve(conn, method, path, token):
    """Runs the request's database work; never commits. Returns a Result."""
    if method != "GET":
        return Result(405, {"error": "read-only gateway"}, "write_attempt")
    for pattern, handler, needs_raw_token in ROUTES:
        match = pattern.fullmatch(path)
        if match:
            break
    else:
        return Result(404, {"error": "not found"}, "unknown_path")
    if token is None:
        return Result(401, {"error": "authentication required"}, handler.__name__.removeprefix("route_"))
    identity = authenticate(conn, token)
    if identity is None:
        return Result(401, {"error": "invalid or expired token"}, handler.__name__.removeprefix("route_"))
    args = (token, *match.groups()) if needs_raw_token else match.groups()
    result = handler(conn, identity, *args)
    result.actor = identity["actor"]
    if result.company_id is None:
        result.company_id = identity["company_id"]
    return result


def process(method, path, headers, request_id, connect=connect):
    """Resolve, audit, commit; only then return (status, payload). Withholds data if auditing fails."""
    conn = None
    try:
        conn = connect()
        try:
            result = resolve(conn, method, path, bearer_token(headers))
        except psycopg.Error:
            conn.rollback()
            result = Result(503, {"error": "database unavailable"}, "database_error")
        conn.execute(AUDIT_SQL, (
            request_id, result.actor, result.action, result.company_id,
            method, path, result.query, result.status, result.outcome,
        ))
        conn.commit()
    except Exception:
        sys.stderr.write(f"gateway audit failure request_id={request_id}; no data returned\n")
        return 503, {**AUDIT_FAILED, "request_id": request_id}
    finally:
        if conn is not None:
            conn.close()
    return result.status, result.payload


def to_json(value):
    return str(value) if isinstance(value, Decimal) else value


class Handler(BaseHTTPRequestHandler):
    def handle_request(self):
        request_id = str(uuid.uuid4())
        if self.command == "GET" and self.path == "/health":
            with connect() as conn:
                up = conn.execute("SELECT 1").fetchone()[0] == 1
            return self.reply(200, {"status": "ok", "database": up}, request_id)
        status, payload = process(self.command, self.path, self.headers, request_id)
        return self.reply(status, payload, request_id)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

    def reply(self, status, payload, request_id):
        body = json.dumps(payload, default=to_json).encode()
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("X-Request-ID", request_id)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Method, path and status only; never headers or tokens.
        sys.stderr.write(f"gateway {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
