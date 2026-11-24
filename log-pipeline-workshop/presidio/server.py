"""log-presidio: fallback sanitiser for logs the Fluent Bit regex path does not recognise.

Fluent Bit posts batches (JSON arrays) to POST /ingest on the private log network.
For each record Presidio analyses the whole record text, but the output never contains
that text: the message is replaced as a whole ("whole-message redaction") and only the
detected entity types and counts are shown, so a detector miss cannot expose anything.
Approved operational fields (service, level, event, sequence) are kept when they are
plain values; every other field is omitted. Output: one JSON line per record on stdout.
"""

import json
import os
import re
import sys
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Exercise 3: sanitised records go back to Fluent Bit (HTTP input) for the standard Loki.
FORWARD_URL = os.environ.get("SANITISED_FORWARD_URL")

OPERATIONAL = {"service", "level", "event", "sequence"}
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_BODY = 5 * 1024 * 1024
_analyzer = None


def analyzer():
    global _analyzer
    if _analyzer is None:
        from recognizers import build_analyzer

        _analyzer = build_analyzer()
    return _analyzer


def record_text(record):
    """Text Presidio inspects: the raw line for malformed input, otherwise the record as JSON."""
    if set(record) <= {"log", "date", "service"} and isinstance(record.get("log"), str):
        return record["log"]
    payload = {k: v for k, v in record.items() if k not in ("date",)}
    return json.dumps(payload, ensure_ascii=False)


def sanitise(record, detect=None):
    detect = detect or (lambda text: analyzer().analyze(text=text, language="en", score_threshold=0.5))
    text = record_text(record)
    results = detect(text)
    counts = Counter(result.entity_type for result in results)
    malformed = set(record) <= {"log", "date", "service"}
    out = {"processing_path": "presidio"}
    for key in sorted(OPERATIONAL):
        value = record.get(key)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, int) or (isinstance(value, str) and SAFE_TOKEN.match(value)):
            out[key] = value
    out["malformed"] = malformed
    out["message"] = "[REDACTED: whole message withheld]"
    out["detections"] = dict(sorted(counts.items()))
    out["detection_count"] = sum(counts.values())
    return out


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, b'{"status":"ok"}')
        return self.reply(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path != "/ingest":
            return self.reply(404, b'{"error":"not found"}')
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self.reply(413, b'{"error":"too large"}')
        try:
            batch = json.loads(self.rfile.read(length))
        except ValueError:
            return self.reply(400, b'{"error":"invalid json"}')
        records = batch if isinstance(batch, list) else [batch]
        try:
            clean = [sanitise(r if isinstance(r, dict) else {"log": str(r)}) for r in records]
            if FORWARD_URL:
                body = json.dumps(clean, ensure_ascii=False).encode()
                request = urllib.request.Request(FORWARD_URL, data=body, method="POST",
                                                 headers={"Content-Type": "application/json"})
                urllib.request.urlopen(request, timeout=10).close()
        except Exception:
            # Fluent Bit retries on 5xx, so nothing is printed raw and nothing is lost.
            return self.reply(503, b'{"error":"analysis or forwarding failed"}')
        lines = [json.dumps(record, ensure_ascii=False) for record in clean]
        sys.stdout.write("".join(line + "\n" for line in lines))
        sys.stdout.flush()
        return self.reply(200, b'{"status":"ok"}')

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # request bodies and paths are never logged


if __name__ == "__main__":
    analyzer()  # load models before accepting traffic
    sys.stderr.write("log-presidio ready\n")
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
