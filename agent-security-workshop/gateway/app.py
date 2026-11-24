"""Read-only database gateway: the only path from agent_net to PostgreSQL on db_net."""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg

CONFIG = json.loads(Path("/run/gateway/connection.json").read_text())


def query(sql):
    with psycopg.connect(**CONFIG, connect_timeout=5) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute(sql)
            columns = [col.name for col in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


ROUTES = {
    "/health": lambda: {"status": "ok", "database": query("SELECT 1 AS up")[0]["up"] == 1},
    "/projects": lambda: query("SELECT project_id, title FROM lab_public.projects ORDER BY project_id"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(self.path)
        if route is None:
            return self.reply(404, {"error": "not found"})
        try:
            return self.reply(200, route())
        except psycopg.Error as exc:
            return self.reply(503, {"error": type(exc).__name__})

    def reject(self):
        self.reply(405, {"error": "read-only gateway"})

    do_POST = do_PUT = do_PATCH = do_DELETE = reject

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"gateway {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
