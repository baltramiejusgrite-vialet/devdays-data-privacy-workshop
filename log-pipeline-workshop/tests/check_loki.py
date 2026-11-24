"""Exercise 3 check: forensic and standard log stores through their Grafana instances.

Usage, from the repository root, with the pipeline running:
    python log-pipeline-workshop/tests/check_loki.py

Reads the Grafana admin passwords from log-pipeline-workshop/.env (never printed).
Raw log lines are never printed; the forensic store is only checked by counts.
"""

import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
from samples import sensitive_values  # noqa: E402

STANDARD = ("http://127.0.0.1:3000", "GRAFANA_ADMIN_PASSWORD", "loki-standard")
FORENSIC = ("http://127.0.0.1:3001", "FORENSIC_GRAFANA_ADMIN_PASSWORD", "loki-forensic")


def env():
    return dict(line.split("=", 1) for line in (LAB / ".env").read_text().splitlines() if "=" in line)


def call(grafana, path, secret=None):
    base, password_key, _ = grafana
    headers = {}
    if secret is not False:
        token = base64.b64encode(f"admin:{env()[password_key]}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(base + path, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as err:
        return err.code, None


def loki(grafana, query, minutes=60):
    now = int(time.time() * 1e9)
    params = urllib.parse.urlencode({"query": query, "start": now - minutes * 60 * 10**9, "end": now, "limit": 5000})
    status, body = call(grafana, f"/api/datasources/proxy/uid/{grafana[2]}/loki/api/v1/query_range?{params}")
    if status != 200:
        return status, []
    # Fluent Bit's Loki output moves label keys (service, processing_path) from the line into stream labels.
    lines = [(stream["stream"], line) for stream in body["data"]["result"] for _, line in stream["values"]]
    return status, lines


def main():
    results = []

    def check(name, ok, detail):
        results.append((name, ok, detail))

    deadline = time.time() + 120
    while time.time() < deadline:
        _, sanitised = loki(STANDARD, '{job="sanitised"}')
        _, raw = loki(FORENSIC, '{job="forensic"}')
        paths = {labels.get("processing_path") for labels, _ in sanitised}
        if raw and {"regex", "presidio"} <= paths:
            break
        time.sleep(5)

    check("forensic store has logs", bool(raw), f"{len(raw)} raw records in loki-forensic")
    check("forensic store keeps raw detail", any(v in line for _, line in raw for v in sensitive_values()),
          "raw personal data present (expected: this is the sensitive store)")
    check("standard store has logs", bool(sanitised), f"{len(sanitised)} sanitised records in loki")
    check("standard store has both processing paths", {"regex", "presidio"} <= paths,
          f"processing_path labels: {sorted(p for p in paths if p)}")
    leaked = sum(1 for labels, line in sanitised for v in sensitive_values() if v in line or v in json.dumps(labels))
    check("standard store has no personal data", leaked == 0, f"{leaked} sensitive value(s) found")
    counts = {p: sum(1 for labels, _ in sanitised if labels.get("processing_path") == p) for p in ("regex", "presidio")}
    check("both paths streamed", all(counts.values()), f"regex={counts['regex']} presidio={counts['presidio']}")

    status, datasources = call(STANDARD, "/api/datasources")
    uids = sorted(d["uid"] for d in datasources or [])
    check("standard Grafana sees only the sanitised store", uids == ["loki-standard"], f"datasources={uids}")
    status, datasources = call(FORENSIC, "/api/datasources")
    uids = sorted(d["uid"] for d in datasources or [])
    check("forensic Grafana sees only the forensic store", uids == ["loki-forensic"], f"datasources={uids}")
    status, _ = call(STANDARD, "/api/datasources/proxy/uid/loki-forensic/loki/api/v1/labels")
    check("standard Grafana cannot query the forensic store", status in (400, 403, 404), f"HTTP {status}")

    for grafana, label in ((STANDARD, "standard"), (FORENSIC, "forensic")):
        status, _ = call(grafana, "/api/search", secret=False)
        check(f"{label} Grafana requires login", status == 401, f"anonymous request -> HTTP {status}")
        status, found = call(grafana, "/api/search?type=dash-db")
        titles = [d["title"] for d in found or []]
        check(f"{label} Grafana dashboard provisioned", bool(titles), f"{titles}")

    retention = {name: next(line.split(":")[1].split("#")[0].strip()
                            for line in (LAB / "loki" / f"loki-{name}.yaml").read_text().splitlines()
                            if "retention_period" in line) for name in ("standard", "forensic")}
    check("retention: forensic 3 years, standard 7 days",
          retention == {"standard": "168h", "forensic": "26280h"}, f"{retention}")

    width = max(len(r[0]) for r in results)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail}")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
