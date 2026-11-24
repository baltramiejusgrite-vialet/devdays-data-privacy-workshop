"""Model broker unit tests with a fake upstream. No API credentials, no paid requests.

Run: python3 -m unittest discover -s tests -p test_model_proxy.py -v
(pytest also collects these.)

Covers 429 enforcement, concurrent requests, durable usage across broker instances,
accounting failure, header ambiguity, sanitized provider errors, credential handling,
and every policy rejection, each proving that rejected requests never reach the upstream.
"""

import hashlib
import http.client
import importlib.util
import json
import shutil
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "model-proxy" / "proxy.py"
spec = importlib.util.spec_from_file_location("model_proxy", APP)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)

MODEL = "test-model"
REAL_KEY = "sk-real-provider-key-for-tests"
CLIENT_TOKEN = "mpx_client-token-for-tests"


class FakeUpstream:
    """Records every request it receives; responds with a configurable status and body."""

    def __init__(self):
        self.requests = []
        self.status = 200
        self.body = b'{"id": "resp_1", "output_text": "READY"}'
        self.lock = threading.Lock()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                with upstream.lock:
                    upstream.requests.append({"path": self.path, "headers": dict(self.headers),
                                              "header_list": self.headers.items(), "body": json.loads(body)})
                self.send_response(upstream.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(upstream.body)))
                self.end_headers()
                self.wfile.write(upstream.body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class BrokerCase(unittest.TestCase):
    limit = 5

    def setUp(self):
        self.state_dir = Path(tempfile.mkdtemp())
        (self.state_dir / "client_token.sha256").write_text(hashlib.sha256(CLIENT_TOKEN.encode()).hexdigest())
        self.upstream = FakeUpstream()
        self.brokers = []
        self.port = self.start_broker()

    def tearDown(self):
        for server in self.brokers:
            server.shutdown()
            server.server_close()
        self.upstream.close()
        shutil.rmtree(self.state_dir, ignore_errors=True)

    def settings(self, **overrides):
        values = dict(api_key=REAL_KEY, model=MODEL, request_limit=self.limit, max_output_tokens=4096,
                      state_dir=self.state_dir, upstream_url=self.upstream.url)
        values.update(overrides)
        return proxy.Settings(**values)

    def start_broker(self, **overrides):
        server = proxy.serve(proxy.Broker(self.settings(**overrides)), host="127.0.0.1", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.brokers.append(server)
        return server.server_address[1]

    def request(self, body=None, path="/v1/responses", method="POST", token=CLIENT_TOKEN, port=None,
                headers=None, raw_headers=None):
        """Sends one request; raw_headers is a list of (name, value) sent verbatim, allowing repeats."""
        payload = json.dumps(body if body is not None else self.valid()).encode() if method == "POST" else b""
        sock = socket.create_connection(("127.0.0.1", port or self.port), timeout=10)
        lines = [f"{method} {path} HTTP/1.1", "Host: model-proxy", "Content-Type: application/json"]
        if token is not None:
            lines.append(f"Authorization: Bearer {token}")
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")
        lines += [f"{n}: {v}" for n, v in (raw_headers or [])]
        if method == "POST" and not any(n.lower() == "content-length" for n, _ in (raw_headers or [])):
            lines.append(f"Content-Length: {len(payload)}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + payload)
        response = http.client.HTTPResponse(sock)
        response.begin()
        data = response.read()
        sock.close()
        return response.status, data.decode()

    @staticmethod
    def valid(**overrides):
        return {"model": MODEL, "input": "hello", **overrides}

    def usage(self):
        path = self.state_dir / "usage.json"
        return json.loads(path.read_text())["requests_used"] if path.exists() else 0


class AllowedRequests(BrokerCase):
    def test_allowed_request_reaches_upstream_and_returns_data(self):
        status, body = self.request()
        self.assertEqual(status, 200)
        self.assertIn("READY", body)
        self.assertEqual(len(self.upstream.requests), 1)
        self.assertEqual(self.upstream.requests[0]["path"], "/v1/responses")

    def test_real_key_replaces_client_token_upstream(self):
        self.request()
        sent = self.upstream.requests[0]["header_list"]
        auth = [v for k, v in sent if k.lower() == "authorization"]
        self.assertEqual(auth, [f"Bearer {REAL_KEY}"])
        self.assertNotIn(CLIENT_TOKEN, json.dumps(sent))

    def test_exactly_one_content_type_upstream(self):
        self.request()
        content_types = [v for k, v in self.upstream.requests[0]["header_list"] if k.lower() == "content-type"]
        self.assertEqual(content_types, ["application/json"])

    def test_output_cap_added_when_missing(self):
        self.request()
        self.assertEqual(self.upstream.requests[0]["body"]["max_output_tokens"], 4096)

    def test_lower_output_limit_kept(self):
        self.request(self.valid(max_output_tokens=200))
        self.assertEqual(self.upstream.requests[0]["body"]["max_output_tokens"], 200)

    def test_function_tools_allowed(self):
        status, _ = self.request(self.valid(tools=[{"type": "function", "name": "shell"}, {"type": "custom", "name": "x"}]))
        self.assertEqual(status, 200)


class Rejections(BrokerCase):
    def assert_rejected(self, expected_status, **kwargs):
        status, body = self.request(**kwargs)
        self.assertEqual(status, expected_status, body)
        self.assertEqual(self.upstream.requests, [], "rejected request must not reach the upstream")
        self.assertEqual(self.usage(), 0, "rejected request must not use budget")
        return body

    def test_missing_authentication(self):
        self.assert_rejected(401, token=None)

    def test_wrong_token(self):
        self.assert_rejected(401, token="mpx_wrong")

    def test_real_provider_key_is_not_a_proxy_token(self):
        self.assert_rejected(401, token=REAL_KEY)

    def test_non_bearer_scheme(self):
        self.assert_rejected(401, token=None, headers={"Authorization": f"Basic {CLIENT_TOKEN}"})

    def test_other_model(self):
        self.assert_rejected(400, body=self.valid(model="gpt-4o"))

    def test_missing_model(self):
        self.assert_rejected(400, body={"input": "hello"})

    def test_other_endpoints(self):
        for path in ["/v1/chat/completions", "/v1/embeddings", "/v1/responses/abc", "/v1/files", "/admin"]:
            with self.subTest(path=path):
                self.assert_rejected(403, path=path)

    def test_get_models_rejected(self):
        self.assert_rejected(403, method="GET", path="/v1/models")

    def test_hosted_tools(self):
        for tool in [{"type": "web_search"}, {"type": "web_search_preview"}, {"type": "file_search"},
                     {"type": "code_interpreter"}, {"type": "image_generation"}, {"type": "computer_use_preview"},
                     {"type": "mcp", "server_url": "https://example.com"}, "web_search", {}]:
            with self.subTest(tool=tool):
                self.assert_rejected(400, body=self.valid(tools=[{"type": "function", "name": "ok"}, tool]))

    def test_tools_not_a_list(self):
        self.assert_rejected(400, body=self.valid(tools={"type": "function"}))

    def test_malformed_output_limits(self):
        for value in [4097, 100000, 0, -1, "4096", 4096.0, True, None, [4096]]:
            with self.subTest(value=value):
                self.assert_rejected(400, body=self.valid(max_output_tokens=value))

    def test_background_requests(self):
        for value in [True, "true", 1]:
            with self.subTest(value=value):
                self.assert_rejected(400, body=self.valid(background=value))

    def test_body_not_json_object(self):
        self.assert_rejected(400, body=["not", "an", "object"])

    def test_compressed_body(self):
        self.assert_rejected(415, headers={"Content-Encoding": "gzip"})


class HeaderAmbiguity(Rejections):
    def test_repeated_authorization(self):
        self.assert_rejected(400, raw_headers=[("Authorization", "Bearer mpx_other")])

    def test_repeated_content_length(self):
        length = len(json.dumps(self.valid()))
        self.assert_rejected(400, raw_headers=[("Content-Length", str(length)), ("Content-Length", str(length))])

    def test_transfer_encoding_with_content_length(self):
        length = len(json.dumps(self.valid()))
        self.assert_rejected(400, raw_headers=[("Transfer-Encoding", "chunked"), ("Content-Length", str(length))])

    def test_repeated_content_type(self):
        self.assert_rejected(400, raw_headers=[("Content-Type", "text/plain")])


class RequestLimit(BrokerCase):
    limit = 3

    def test_429_after_limit(self):
        statuses = [self.request()[0] for _ in range(5)]
        self.assertEqual(statuses, [200, 200, 200, 429, 429])
        self.assertEqual(len(self.upstream.requests), 3)
        self.assertEqual(self.usage(), 3)

    def test_rejected_429_never_reaches_upstream(self):
        for _ in range(3):
            self.request()
        self.upstream.requests.clear()
        status, body = self.request()
        self.assertEqual(status, 429)
        self.assertIn("budget", body)
        self.assertEqual(self.upstream.requests, [])

    def test_failed_upstream_attempt_uses_a_slot(self):
        self.upstream.status = 500
        self.assertEqual(self.request()[0], 500)
        self.assertEqual(self.usage(), 1)

    def test_unreachable_upstream_uses_a_slot(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        broker_port = self.start_broker(upstream_url=f"http://127.0.0.1:{port}")
        status, body = self.request(port=broker_port)
        self.assertEqual(status, 502)
        self.assertEqual(self.usage(), 1)

    def test_usage_endpoint_reports_budget(self):
        self.request()
        status, body = self.request(method="GET", path="/usage")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["requests_used"], 1)
        self.assertEqual(json.loads(body)["request_limit"], 3)


class Concurrency(BrokerCase):
    limit = 5

    def test_concurrent_requests_never_exceed_limit(self):
        results = []
        lock = threading.Lock()

        def worker():
            status, _ = self.request()
            with lock:
                results.append(status)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(200), 5)
        self.assertEqual(results.count(429), 15)
        self.assertEqual(len(self.upstream.requests), 5)
        self.assertEqual(self.usage(), 5)


class Durability(BrokerCase):
    limit = 4

    def test_usage_shared_and_kept_across_broker_instances(self):
        self.request()
        self.request()
        second = self.start_broker()
        self.assertEqual(self.request(port=second)[0], 200)
        self.assertEqual(self.request(port=second)[0], 200)
        self.assertEqual(self.request()[0], 429)
        self.assertEqual(self.request(port=second)[0], 429)

    def test_restart_does_not_reset_budget(self):
        for _ in range(4):
            self.request()
        for server in self.brokers:
            server.shutdown()
            server.server_close()
        self.brokers.clear()
        restarted = self.start_broker()
        self.assertEqual(self.request(port=restarted)[0], 429)


class AccountingFailure(BrokerCase):
    def test_corrupt_usage_record_withholds_request(self):
        (self.state_dir / "usage.json").write_text("{not json")
        status, body = self.request()
        self.assertEqual(status, 503)
        self.assertIn("accounting", body)
        self.assertEqual(self.upstream.requests, [])

    def test_invalid_usage_value_withholds_request(self):
        (self.state_dir / "usage.json").write_text('{"requests_used": -3}')
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(self.upstream.requests, [])

    def test_missing_state_directory_withholds_request(self):
        port = self.start_broker(state_dir=self.state_dir / "missing")
        status, _ = self.request(port=port)
        self.assertIn(status, (401, 503))
        self.assertEqual(self.upstream.requests, [])

    def test_unwritable_usage_record_withholds_request(self):
        (self.state_dir / "usage.json").mkdir()
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(self.upstream.requests, [])


class SanitizedErrors(BrokerCase):
    def test_provider_error_body_not_passed_through(self):
        self.upstream.status = 401
        self.upstream.body = json.dumps({"error": {
            "message": f"Incorrect API key provided: {REAL_KEY}. Organization org-secret.",
            "type": "invalid_request_error", "code": "invalid_api_key"}}).encode()
        status, body = self.request()
        self.assertEqual(status, 401)
        self.assertNotIn(REAL_KEY, body)
        self.assertNotIn("org-secret", body)
        self.assertEqual(json.loads(body), {"error": {"message": "model provider returned an error", "status": 401}})

    def test_provider_server_error_sanitized(self):
        self.upstream.status = 500
        self.upstream.body = b"Traceback: internal provider stack trace with internal hostnames"
        status, body = self.request()
        self.assertEqual(status, 500)
        self.assertNotIn("Traceback", body)

    def test_real_key_never_in_any_response(self):
        for kwargs in [{}, {"token": None}, {"body": self.valid(model="x")}, {"path": "/v1/models", "method": "GET"},
                       {"path": "/usage", "method": "GET"}]:
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                _, body = self.request(**kwargs)
                self.assertNotIn(REAL_KEY, body)


if __name__ == "__main__":
    unittest.main()
