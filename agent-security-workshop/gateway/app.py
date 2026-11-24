"""Read-only database gateway: the only path from agent_net to PostgreSQL on db_net.

Logs in as lab_gateway, which can only read public projects and call the
company salary aggregate. Individual salary rows are never available.
"""

import json
import re
import sys
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg

CONFIG = json.loads(Path("/run/gateway/connection.json").read_text())


class NotFound(Exception):
    pass


class Forbidden(Exception):
    pass


def query(sql, params=()):
    with psycopg.connect(**CONFIG, connect_timeout=5) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute(sql, params)
            columns = [col.name for col in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


def health():
    return {"status": "ok", "database": query("SELECT 1 AS up")[0]["up"] == 1}


def projects():
    return {"items": query("SELECT project_id, title FROM lab_public.projects ORDER BY project_id")}


def salary_summary(company_id):
    row = query(
        "SELECT company_id, employee_count, average_salary_eur FROM lab_api.company_salary_summary(%s)",
        (company_id,),
    )[0]
    if row["employee_count"] == 0:
        raise NotFound
    return row


def individual_salaries(company_id):
    raise Forbidden


ROUTES = [
    (re.compile(r"/health"), health),
    (re.compile(r"/projects"), projects),
    (re.compile(r"/companies/(\d{1,9})/salary-summary"), lambda cid: salary_summary(int(cid))),
    (re.compile(r"/companies/(\d{1,9})/salaries(?:/.*)?"), individual_salaries),
]


def to_json(value):
    return str(value) if isinstance(value, Decimal) else value


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        for pattern, handler in ROUTES:
            match = pattern.fullmatch(self.path)
            if match:
                break
        else:
            return self.reply(404, {"error": "not found"})
        try:
            return self.reply(200, handler(*match.groups()))
        except Forbidden:
            return self.reply(403, {"error": "individual salaries are not available"})
        except NotFound:
            return self.reply(404, {"error": "not found"})
        except psycopg.Error as exc:
            return self.reply(503, {"error": type(exc).__name__})

    def reject(self):
        self.reply(405, {"error": "read-only gateway"})

    do_POST = do_PUT = do_PATCH = do_DELETE = reject

    def reply(self, status, payload):
        body = json.dumps(payload, default=to_json).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"gateway {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
