"""Exercise 1 sanitisation tests. Run in the processor container:
    docker compose -f log-pipeline-workshop/docker-compose.yml run --rm processor python -m unittest discover -s tests -v
"""

import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import starter  # noqa: E402
from samples import PEOPLE, event, sensitive_values  # noqa: E402

LEAK_VALUES = sorted(sensitive_values() | {"azuolas@example.com", "ula@example.com"}, key=len, reverse=True)


def leaks(text):
    return [value for value in LEAK_VALUES if value in text]


class SanitiseSampleEvents(unittest.TestCase):
    def test_every_sample_format_is_clean(self):
        for service in ("hr", "billing"):
            for sequence in range(10):  # covers both message formats and both people
                with self.subTest(service=service, sequence=sequence):
                    out = json.dumps(starter.sanitise_record(event(service, sequence), service), ensure_ascii=False)
                    self.assertEqual(leaks(out), [])

    def test_operational_fields_preserved(self):
        clean = starter.sanitise_record(event("hr", 3), "hr")
        self.assertEqual((clean["service"], clean["level"], clean["event"], clean["sequence"]),
                         ("hr", "INFO", "salary_export", 3))

    def test_sensitive_fields_redacted_with_kind(self):
        clean = starter.sanitise_record(event("billing", 0), "billing")
        self.assertEqual(clean["national_id"], "[REDACTED:national_id]")
        self.assertEqual(clean["email"], "[REDACTED:email]")
        self.assertEqual(clean["salary_eur"], "[REDACTED:financial]")
        self.assertEqual(clean["company_profit_eur"], "[REDACTED:financial]")
        self.assertEqual(clean["employee_name"], "[REDACTED:name]")

    def test_nested_fields_sanitised(self):
        clean = starter.sanitise_record(event("hr", 0), "hr")
        self.assertEqual(clean["debug"], {"customer": {"email": "[REDACTED:email]"}})
        self.assertEqual(clean["labels"], {"employee": "[REDACTED:name]"})

    def test_free_text_message_keeps_structure(self):
        clean = starter.sanitise_record(event("hr", 0), "hr")["message"]
        self.assertTrue(clean.startswith("Anketa: darbuotojas="))
        self.assertIn("būsena=gerai", clean)
        self.assertEqual(leaks(clean), [])

    def test_english_message_format_clean(self):
        clean = starter.sanitise_record(event("hr", 4), "hr")["message"]
        self.assertTrue(clean.startswith("Support note: contact"))
        self.assertEqual(leaks(clean), [])


class SanitiseUnknownShapes(unittest.TestCase):
    def test_unknown_field_with_pii_in_text(self):
        record = {"level": "WARN", "event": "x", "note": "call 0612 34 567 or mail a.b@test.lt, code 39001010011, "
                                                         "IBAN LT12 1000 0111 0100 1000, paid 120,50 EUR"}
        note = starter.sanitise_record(record, "hr")["note"]
        for value in ("0612 34 567", "a.b@test.lt", "39001010011", "LT12 1000 0111 0100 1000", "120,50 EUR"):
            self.assertNotIn(value, note)

    def test_list_of_emails(self):
        clean = starter.sanitise_record({"contacts": ["test@example.com", "example@test.com"]}, "hr")
        self.assertNotIn("@", json.dumps(clean))

    def test_context_email(self):
        clean = starter.sanitise_record({"context": {"email": "summit@example.com"}}, "hr")
        self.assertEqual(clean["context"], {"email": "[REDACTED:email]"})

    def test_deep_nesting(self):
        record = {"a": {"b": [{"c": {"phone": "069876543", "ok": 1}}]}}
        self.assertEqual(starter.sanitise_record(record, "hr")["a"], {"b": [{"c": {"phone": "[REDACTED:phone]", "ok": 1}}]})

    def test_non_sensitive_values_kept(self):
        record = {"level": "INFO", "event": "health", "sequence": 7, "duration_ms": 12, "status": "ok"}
        clean = starter.sanitise_record(record, "billing")
        self.assertEqual({k: clean[k] for k in record}, record)


class BatchProcessing(unittest.TestCase):
    def write(self, folder, name, lines):
        path = Path(folder) / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_malformed_records_skipped_without_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write(folder, "app.jsonl", [json.dumps(event("hr", 0)),
                                                    '{"message": "SECRET_TEST_MARKER 39001010011", broken',
                                                    "[1, 2]", json.dumps(event("hr", 1))])
            out, err = io.StringIO(), io.StringIO()
            printed, skipped = starter.process({"hr": path}, out=out, err=err)
            self.assertEqual((printed, skipped), (2, 2))
            self.assertNotIn("SECRET_TEST_MARKER", out.getvalue() + err.getvalue())
            self.assertNotIn("39001010011", out.getvalue() + err.getvalue())
            self.assertIn("hr:2", err.getvalue())

    def test_source_file_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write(folder, "app.jsonl", [json.dumps(event("billing", i)) for i in range(5)])
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            starter.process({"billing": path}, out=io.StringIO(), err=io.StringIO())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_batch_size_respected_and_output_is_json_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write(folder, "app.jsonl", [json.dumps(event("hr", i)) for i in range(30)])
            out = io.StringIO()
            starter.process({"hr": path}, batch_size=10, out=out, err=io.StringIO())
            lines = out.getvalue().splitlines()
            self.assertEqual(len(lines), 10)
            self.assertTrue(all(json.loads(line)["service"] == "hr" for line in lines))

    def test_missing_source_is_not_an_error(self):
        printed, skipped = starter.process({"hr": Path("/nonexistent/app.jsonl")}, out=io.StringIO(), err=io.StringIO())
        self.assertEqual((printed, skipped), (0, 0))


@unittest.skipUnless(Path("/raw/hr/app.jsonl").exists(), "needs the processor container with raw log volumes")
class LiveBatch(unittest.TestCase):
    def test_live_batch_has_no_sample_pii(self):
        out = io.StringIO()
        printed, _ = starter.process(batch_size=50, out=out, err=io.StringIO())
        self.assertGreater(printed, 0)
        self.assertEqual(leaks(out.getvalue()), [])
