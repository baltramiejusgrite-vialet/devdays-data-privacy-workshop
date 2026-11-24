"""Exercise 4, step 2: the production and pseudo-prod schemas must match the code-defined schema.

Run inside the runner:
    docker compose run --rm refresh-runner python -m unittest discover -s tests -p test_schema_contract.py -v

These tests are expected to FAIL while production has a column the code does not know
(e.g. after adding company.address) — that failure is what stops the clone.
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import compare_schemas  # noqa: E402
import pseudo_prod_schema as contract  # noqa: E402
from describe_schema import render_schema  # noqa: E402


class ContractUnitTests(unittest.TestCase):
    def test_every_column_has_a_method(self):
        for table, columns in contract.PSEUDO_PROD_SCHEMA.items():
            for column, (column_type, rule) in columns.items():
                with self.subTest(column=f"{table}.{column}"):
                    self.assertIn(rule.method, {"copy", "hmac_email", "hmac_national_id", "mask"})
                    self.assertTrue(column_type)

    def test_identifiers_use_hmac_and_personal_fields_are_masked(self):
        people = contract.PSEUDO_PROD_SCHEMA["business.people"]
        self.assertEqual(people["email"][1].method, "hmac_email")
        self.assertEqual(people["national_id"][1].method, "hmac_national_id")
        for column in ("first_name", "last_name", "birth_date"):
            self.assertEqual(people[column][1].method, "mask")

    def test_unknown_column_detected(self):
        actual = contract.expected_schema()
        actual["business.companies"] = sorted(actual["business.companies"] + [("address", "text")])
        self.assertEqual(contract.schema_differences(actual),
                         ["unknown column business.companies.address (text): no pseudonymisation rule defined"])

    def test_compare_reports_difference(self):
        self.assertTrue(compare_schemas.compare("table a\n  x: int\n", "table a\n  x: int\n  y: text\n"))
        self.assertEqual(compare_schemas.compare("same\n", "same\n"), "")


@unittest.skipUnless(os.environ.get("SOURCE_DSN") and os.environ.get("PSEUDO_PROD_DSN"), "needs the runner container")
class LiveSchemaTests(unittest.TestCase):
    def live(self, env):
        import psycopg

        with psycopg.connect(os.environ[env], autocommit=True) as conn:
            return contract.business_schema(conn)

    def test_production_schema_matches_code(self):
        self.assertEqual(contract.schema_differences(self.live("SOURCE_DSN")), [])

    def test_pseudo_prod_schema_matches_code(self):
        self.assertEqual(contract.schema_differences(self.live("PSEUDO_PROD_DSN")), [])

    def test_production_and_pseudo_prod_descriptions_identical(self):
        self.assertEqual(render_schema(self.live("SOURCE_DSN")), render_schema(self.live("PSEUDO_PROD_DSN")))
