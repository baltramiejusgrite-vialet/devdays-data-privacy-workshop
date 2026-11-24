"""log-presidio unit tests. Run in the service image:
    docker compose -f log-pipeline-workshop/docker-compose.yml run --rm --no-deps log-presidio python -m unittest discover -s /pipeline/tests -v
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

UNKNOWN = ("Support note: contact Ąžuolas Žukauskas at azuolas@example.com; phone 0612 34 567; "
           "delivery Žalgirio g. 18-7, Vilnius; national ID 39001010011; amount 4250 EUR")


def detected(text):
    return {r.entity_type for r in server.analyzer().analyze(text=text, language="en", score_threshold=0.5)}


class RecognizerTests(unittest.TestCase):
    def test_lithuanian_national_id(self):
        self.assertIn("LT_NATIONAL_ID", detected("asmens kodas 39001010011"))

    def test_lithuanian_phone(self):
        self.assertIn("LT_PHONE", detected("telefonas 0612 34 567"))

    def test_email(self):
        self.assertIn("EMAIL_ADDRESS", detected("mail summit@example.com"))

    def test_address(self):
        self.assertIn("LT_ADDRESS", detected("adresas Žalgirio g. 18-7, Vilnius"))

    def test_iban(self):
        self.assertTrue({"LT_IBAN", "IBAN_CODE"} & detected("account LT12 1000 0111 0100 1000"))

    def test_lithuanian_name_after_label(self):
        self.assertIn("LT_PERSON", detected("darbuotojas=Rūta Kazlauskaitė; būsena=gerai"))

    def test_unknown_support_note_has_many_detections(self):
        found = detected(UNKNOWN)
        for entity in ("EMAIL_ADDRESS", "LT_PHONE", "LT_NATIONAL_ID", "LT_ADDRESS", "EUR_AMOUNT"):
            self.assertIn(entity, found)


class SanitiseTests(unittest.TestCase):
    def test_whole_message_withheld_and_counts_reported(self):
        out = server.sanitise({"service": "hr", "level": "INFO", "event": "salary_export", "sequence": 4,
                               "message": UNKNOWN, "email": "azuolas@example.com"})
        text = json.dumps(out, ensure_ascii=False)
        for value in ("Žukauskas", "azuolas@example.com", "0612 34 567", "39001010011", "Žalgirio", "4250"):
            self.assertNotIn(value, text)
        self.assertEqual(out["processing_path"], "presidio")
        self.assertEqual((out["service"], out["event"], out["sequence"]), ("hr", "salary_export", 4))
        self.assertGreater(out["detection_count"], 0)

    def test_detector_miss_still_leaks_nothing(self):
        out = server.sanitise({"service": "hr", "message": "SECRET_TEST_MARKER totally unknown"},
                              detect=lambda text: [])
        self.assertNotIn("SECRET_TEST_MARKER", json.dumps(out))
        self.assertEqual(out["detection_count"], 0)

    def test_malformed_line_flagged_and_withheld(self):
        out = server.sanitise({"service": "billing", "log": '{"message": "SECRET_TEST_MARKER 39001010011", oops'})
        self.assertTrue(out["malformed"])
        self.assertNotIn("SECRET_TEST_MARKER", json.dumps(out))
        self.assertIn("LT_NATIONAL_ID", out["detections"])

    def test_unsafe_operational_values_dropped(self):
        out = server.sanitise({"service": "hr", "event": "contact azuolas@example.com"}, detect=lambda text: [])
        self.assertNotIn("event", out)

    def test_nested_fields_never_copied(self):
        out = server.sanitise({"service": "hr", "context": {"email": "summit@example.com"},
                               "contacts": ["test@example.com", "example@test.com"]})
        self.assertNotIn("@", json.dumps(out))
        self.assertEqual(out["detections"].get("EMAIL_ADDRESS"), 3)
