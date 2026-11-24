"""Model broker: the agent's only route to OpenAI.

Holds the real OpenAI key; the agent never does. Enforced on every request:
  * authentication with a separate local proxy token (only its SHA-256 hash is stored here)
  * one endpoint (POST /v1/responses) and one fixed model
  * an output cap (max_output_tokens <= 4096; set to the cap when omitted)
  * no hosted tools and no background requests
  * a persistent request budget (60 by default) shared by every broker instance and
    surviving restarts; a slot is reserved before the upstream call, so failed attempts count
  * unambiguous headers (one Authorization, one Content-Length, no Transfer-Encoding mix)
  * provider errors are replaced by a generic message
Requests that fail validation never reach OpenAI and use no budget.
"""

import hashlib
import hmac
import http.client
import json
import os
import ssl
import sys
import threading
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ALLOWED_TOOL_TYPES = {"function", "custom", "local_shell"}
MAX_BODY_BYTES = 4 * 1024 * 1024
DROP_HEADERS = {
    "authorization", "connection", "content-length", "host", "keep-alive", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-encoding",
}


class Rejected(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class AccountingError(Exception):
    pass


@dataclass
class Settings:
    api_key: str
    model: str
    request_limit: int
    max_output_tokens: int
    state_dir: Path
    upstream_url: str = "https://api.openai.com"

    @property
    def token_hash_file(self):
        return self.state_dir / "client_token.sha256"

    @classmethod
    def from_env(cls):
        return cls(
            api_key=os.environ["OPENAI_API_KEY"],
            model=os.environ["MODEL_PROXY_MODEL"],
            request_limit=int(os.environ.get("MODEL_PROXY_REQUEST_LIMIT", "60")),
            max_output_tokens=int(os.environ.get("MODEL_PROXY_MAX_OUTPUT_TOKENS", "4096")),
            state_dir=Path(os.environ.get("MODEL_PROXY_STATE_DIR", "/var/lib/model-proxy")),
            upstream_url=os.environ.get("MODEL_PROXY_UPSTREAM", "https://api.openai.com"),
        )


@contextmanager
def file_lock(path):
    """Exclusive lock shared by every process (and broker instance) using the same state dir."""
    with open(path, "a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


class UsageLedger:
    """Durable request counter in <state_dir>/usage.json."""

    _thread_lock = threading.Lock()

    def __init__(self, state_dir, limit):
        self.path = Path(state_dir) / "usage.json"
        self.lock_path = Path(state_dir) / "usage.lock"
        self.limit = limit

    @contextmanager
    def _locked(self):
        try:
            with self._thread_lock, file_lock(self.lock_path):
                yield
        except (OSError, ValueError) as exc:
            raise AccountingError(str(exc)) from exc

    def _read(self):
        if not self.path.exists():
            return 0
        used = json.loads(self.path.read_text())["requests_used"]
        if not isinstance(used, int) or isinstance(used, bool) or used < 0:
            raise ValueError("corrupt usage record")
        return used

    def _write(self, used):
        temp = self.path.with_name("usage.json.tmp")
        with open(temp, "w") as handle:
            json.dump({"requests_used": used}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)

    def used(self):
        try:
            with self._locked():
                return self._read()
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AccountingError(str(exc)) from exc

    def reserve(self):
        """Takes one slot or raises Rejected(429). Any storage problem raises AccountingError."""
        try:
            with self._locked():
                used = self._read()
                if used >= self.limit:
                    raise Rejected(429, f"request budget of {self.limit} requests is used up")
                self._write(used + 1)
                return used + 1
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AccountingError(str(exc)) from exc


class Broker:
    def __init__(self, settings):
        self.settings = settings
        self.ledger = UsageLedger(settings.state_dir, settings.request_limit)
        upstream = urllib.parse.urlsplit(settings.upstream_url)
        self.upstream_scheme = upstream.scheme
        self.upstream_host = upstream.hostname
        self.upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)

    # --- checks -------------------------------------------------------------

    def check_headers(self, headers):
        for name in ("Authorization", "Content-Length", "Content-Type", "Host", "Transfer-Encoding"):
            if len(headers.get_all(name) or []) > 1:
                raise Rejected(400, f"ambiguous request: repeated {name} header")
        if headers.get("Transfer-Encoding") and headers.get("Content-Length"):
            raise Rejected(400, "ambiguous request: both Transfer-Encoding and Content-Length")
        if headers.get("Transfer-Encoding"):
            raise Rejected(400, "chunked request bodies are not accepted")

    def authenticate(self, headers):
        scheme, _, token = (headers.get("Authorization") or "").partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise Rejected(401, "proxy authentication required")
        try:
            expected = self.settings.token_hash_file.read_text().strip()
        except OSError:
            raise Rejected(503, "proxy token is not configured")
        actual = hashlib.sha256(token.encode()).hexdigest()
        if not expected or not hmac.compare_digest(actual, expected):
            raise Rejected(401, "invalid proxy token")

    def read_json_body(self, headers, rfile):
        if (headers.get("Content-Encoding") or "identity").lower() != "identity":
            raise Rejected(415, "compressed request bodies are not accepted")
        length = headers.get("Content-Length")
        if length is None or not length.isdigit():
            raise Rejected(411, "a valid Content-Length is required")
        length = int(length)
        if length > MAX_BODY_BYTES:
            raise Rejected(413, "request body too large")
        try:
            body = json.loads(rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise Rejected(400, "request body must be JSON")
        if not isinstance(body, dict):
            raise Rejected(400, "request body must be a JSON object")
        return body

    def enforce_policy(self, body):
        if body.get("model") != self.settings.model:
            raise Rejected(400, f"only model {self.settings.model} is allowed")
        if body.get("background") not in (None, False):
            raise Rejected(400, "background requests are not allowed")
        tools = body.get("tools", [])
        if not isinstance(tools, list) or any(
            not isinstance(tool, dict) or tool.get("type") not in ALLOWED_TOOL_TYPES for tool in tools
        ):
            raise Rejected(400, "hosted tools are not allowed")
        cap = self.settings.max_output_tokens
        limit = body.get("max_output_tokens", cap)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= cap:
            raise Rejected(400, f"max_output_tokens must be an integer from 1 to {cap}")
        body["max_output_tokens"] = limit
        return body

    # --- upstream -----------------------------------------------------------

    def open_upstream(self, body, client_headers):
        # Content-Type is dropped too and set once below, so the provider never sees two.
        headers = {k: v for k, v in client_headers.items() if k.lower() not in DROP_HEADERS | {"content-type"}}
        headers["Authorization"] = f"Bearer {self.settings.api_key}"
        headers["Content-Type"] = "application/json"
        if self.upstream_scheme == "https":
            conn = http.client.HTTPSConnection(self.upstream_host, self.upstream_port, timeout=300,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=300)
        conn.request("POST", "/v1/responses", body=json.dumps(body).encode(), headers=headers)
        return conn, conn.getresponse()

    def status_payload(self):
        return {
            "model": self.settings.model,
            "endpoint": "POST /v1/responses",
            "max_output_tokens": self.settings.max_output_tokens,
            "request_limit": self.settings.request_limit,
            "requests_used": self.ledger.used(),
        }


def make_handler(broker):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                if self.path == "/health":
                    return self.reply_json(200, {"status": "ok"})
                if self.path == "/usage":
                    broker.check_headers(self.headers)
                    broker.authenticate(self.headers)
                    return self.reply_json(200, broker.status_payload())
                raise Rejected(403, "only POST /v1/responses is proxied")
            except Rejected as err:
                return self.reply_json(err.status, {"error": {"message": err.message}})
            except AccountingError:
                return self.reply_json(503, {"error": {"message": "usage accounting unavailable"}})

        def do_POST(self):
            try:
                if self.path != "/v1/responses":
                    raise Rejected(403, "only POST /v1/responses is proxied")
                broker.check_headers(self.headers)
                broker.authenticate(self.headers)
                body = broker.enforce_policy(broker.read_json_body(self.headers, self.rfile))
                broker.ledger.reserve()
            except Rejected as err:
                self.close_connection = True
                sys.stderr.write(f"model-proxy rejected {self.path}: {err.message}\n")
                return self.reply_json(err.status, {"error": {"message": err.message}})
            except AccountingError:
                self.close_connection = True
                sys.stderr.write("model-proxy usage accounting unavailable; request not forwarded\n")
                return self.reply_json(503, {"error": {"message": "usage accounting unavailable"}})
            return self.forward(body)

        def forward(self, body):
            conn = None
            try:
                try:
                    conn, response = broker.open_upstream(body, self.headers)
                except (OSError, http.client.HTTPException):
                    return self.reply_json(502, {"error": {"message": "model provider unavailable"}})
                if response.status >= 400:
                    self.log_provider_error(response.status, response.read())
                    return self.reply_json(response.status, {"error": {
                        "message": "model provider returned an error", "status": response.status}})
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in DROP_HEADERS:
                        self.send_header(key, value)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                while chunk := response.read1(65536):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            finally:
                if conn is not None:
                    conn.close()
                self.close_connection = True

        @staticmethod
        def log_provider_error(status, raw):
            # Operator log only: the provider's error type, code and parameter name, never its message.
            try:
                error = json.loads(raw).get("error") or {}
                fields = {k: error.get(k) for k in ("type", "code", "param") if isinstance(error.get(k), str)}
            except (ValueError, AttributeError):
                fields = {}
            sys.stderr.write(f"model-proxy provider error status={status} {json.dumps(fields)}\n")

        do_PUT = do_PATCH = do_DELETE = lambda self: self.reply_json(
            403, {"error": {"message": "only POST /v1/responses is proxied"}})

        def reply_json(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            # Method, path and status only; never headers, tokens or bodies.
            sys.stderr.write(f"model-proxy {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")

    return Handler


def serve(broker, host="0.0.0.0", port=8080):
    server = ThreadingHTTPServer((host, port), make_handler(broker))
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    serve(Broker(Settings.from_env())).serve_forever()
