"""Model proxy: the agent's only route to OpenAI. Holds the real API key; the agent never does."""

import http.client
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = "api.openai.com"
API_KEY = os.environ["OPENAI_API_KEY"]
DROP_HEADERS = {
    "authorization", "connection", "content-length", "host", "keep-alive",
    "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
TLS = ssl.create_default_context()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/health":
            return self.reply_json(200, {"status": "ok"})
        return self.forward()

    def do_POST(self):
        return self.forward()

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            parts = []
            while size := int(self.rfile.readline().split(b";")[0].strip(), 16):
                parts.append(self.rfile.read(size))
                self.rfile.readline()
            self.rfile.readline()
            return b"".join(parts)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else None

    def forward(self):
        if not self.path.startswith("/v1/"):
            return self.reply_json(403, {"error": "only /v1/ model API paths are proxied"})
        body = self.read_body()
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_HEADERS}
        headers["Authorization"] = f"Bearer {API_KEY}"
        upstream = http.client.HTTPSConnection(UPSTREAM, 443, timeout=300, context=TLS)
        try:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
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
            upstream.close()
            self.close_connection = True

    def reply_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"model-proxy {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
