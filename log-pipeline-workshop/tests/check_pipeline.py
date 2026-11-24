"""Repeatable Fluent Bit + Presidio integration check (log pipeline exercise 2).

Usage, from the repository root (Docker required):
    python log-pipeline-workshop/tests/check_pipeline.py

Starts a separate compose project with its own disposable volumes, writes controlled
log lines into the raw HR log, waits for them to come out of the pipeline, checks the
route each record took and that no sensitive value appears in any output, then removes
the project and its volumes. Sensitive values are checked, never printed.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-p", "devdays-log-pipeline-check", "-f",
           str(ROOT / "log-pipeline-workshop" / "docker-compose.yml"), "--profile", "pipeline"]
sys.path.insert(0, str(ROOT / "log-pipeline-workshop"))
from samples import event, sensitive_values  # noqa: E402

KNOWN = event("hr", 0)["message"]       # Lithuanian "Anketa:" format: regex path
UNKNOWN = event("hr", 4)["message"]     # English support note: Presidio path
LITHUANIAN_PII = ("Klientas Rūta Kazlauskaitė paskambino, asmens kodas 48812120044, "
                  "tel. +370 612 34567, gyvena Liepų g. 12-3, Kaunas")

CASES = [
    # name, line written to the raw log, expected route, extra values that must not leak
    ("regex_detectable", {"level": "INFO", "event": "check_regex", "sequence": 1, "message": KNOWN}, "regex", []),
    ("not_regex_detectable", {"level": "INFO", "event": "check_unknown", "sequence": 2, "message": UNKNOWN}, "presidio", []),
    ("context_email", {"level": "INFO", "event": "check_context", "sequence": 3, "message": KNOWN,
                       "context": {"email": "summit@example.com"}}, "regex", ["summit@example.com"]),
    ("contacts_list", {"level": "INFO", "event": "check_contacts", "sequence": 4, "message": UNKNOWN,
                       "contacts": ["test@example.com", "example@test.com"]}, "presidio",
     ["test@example.com", "example@test.com"]),
    ("lithuanian_pii", {"level": "INFO", "event": "check_lithuanian", "sequence": 5, "message": LITHUANIAN_PII},
     "presidio", ["Rūta", "Kazlauskaitė", "48812120044", "+370 612 34567", "Liepų g. 12-3"]),
]
MALFORMED = [
    '{"level": "INFO", "event": "check_malformed", "message": "unterminated',
    '{"event": "check_secret", "message": "SECRET_TEST_MARKER asmens kodas 39001010011", oops}',
]
FORBIDDEN = sorted(sensitive_values() | {"SECRET_TEST_MARKER"} | {v for c in CASES for v in c[3]}, key=len, reverse=True)


def compose(*args, check=True, capture=True):
    return subprocess.run([*COMPOSE, *args], cwd=ROOT, capture_output=capture, text=True, encoding="utf-8",
                          check=check, stdin=subprocess.DEVNULL, timeout=900)


def write_raw_lines(lines):
    payload = "".join(line + "\n" for line in lines)
    code = "import sys; open('/raw/app.jsonl', 'a', encoding='utf-8').write(sys.stdin.read())"
    subprocess.run([*COMPOSE, "run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "app-hr", "-c", code],
                   cwd=ROOT, input=payload, text=True, encoding="utf-8", capture_output=True, check=True, timeout=300)


def outputs():
    def json_lines(service):
        text = compose("logs", "--no-log-prefix", service).stdout
        rows = []
        for line in text.splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
        return rows, text
    regex, regex_text = json_lines("processor")
    presidio, presidio_text = json_lines("log-presidio")
    return regex, presidio, regex_text + presidio_text


def main():
    results = []
    try:
        print("Starting a disposable pipeline (processor + log-presidio)...", flush=True)
        compose("up", "-d", "--build", "--wait", "processor")
        write_raw_lines([json.dumps(case[1], ensure_ascii=False) for case in CASES] + MALFORMED)
        expected_events = {case[1]["event"] for case in CASES}
        deadline = time.time() + 120
        while True:
            regex, presidio, all_text = outputs()
            seen = {r.get("event") for r in regex + presidio}
            malformed = [r for r in presidio if r.get("malformed")]
            if (expected_events <= seen and len(malformed) >= len(MALFORMED)) or time.time() > deadline:
                break
            time.sleep(2)

        by_event = {}
        for row in regex + presidio:
            by_event.setdefault(row.get("event"), row)
        for name, record, route, _ in CASES:
            row = by_event.get(record["event"])
            ok = row is not None and row["processing_path"] == route
            detail = "missing" if row is None else f"processing_path={row['processing_path']}"
            if row is not None and route == "presidio":
                detail += f" detections={row['detections']}"
            results.append((name, f"routed to {route}", ok, detail))
        results.append(("malformed_json", "routed to presidio, flagged malformed", len(malformed) >= len(MALFORMED),
                        f"{len(malformed)} malformed record(s), contents withheld"))
        lithuanian = by_event.get("check_lithuanian", {}).get("detections", {})
        for entity in ("LT_PERSON", "LT_NATIONAL_ID", "LT_PHONE", "LT_ADDRESS"):
            results.append((f"lithuanian_pii:{entity}", "detected by Presidio", entity in lithuanian,
                            f"count={lithuanian.get(entity, 0)}"))
        leaked = [value for value in FORBIDDEN if value in all_text]
        results.append(("no_sensitive_output", "no PII or SECRET_TEST_MARKER in any output", not leaked,
                         f"{len(leaked)} leaked value(s)" + (f" (kinds hidden, count {len(leaked)})" if leaked else "")))
    finally:
        compose("down", "-v", "--remove-orphans", check=False)

    width = max(len(r[0]) for r in results)
    for name, expectation, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}  {expectation}: {detail}")
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
