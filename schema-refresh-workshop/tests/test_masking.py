"""Exercise 3: scan pseudo-prod and check every masked field holds its fixed value.

Run inside the runner:
    docker compose run --rm refresh-runner python -m unittest discover -s tests -p test_masking.py -v
"""

import datetime as dt
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mask_pseudo_prod as mask  # noqa: E402


@unittest.skipUnless(os.environ.get("PSEUDO_PROD_DSN") and os.environ.get("SOURCE_DSN"), "needs the runner container")
class MaskingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        cls.psycopg = psycopg
        cls.target = psycopg.connect(os.environ["PSEUDO_PROD_DSN"], autocommit=True)
        cls.source = psycopg.connect(os.environ["SOURCE_DSN"], autocommit=True)

    @classmethod
    def tearDownClass(cls):
        cls.target.close()
        cls.source.close()

    def distinct(self, conn, table, column):
        return conn.execute(f"SELECT DISTINCT {column} FROM business.{table}").fetchall()

    def test_all_first_names_masked(self):
        self.assertEqual(self.distinct(self.target, "people", "first_name"), [("Person Anonymous",)])

    def test_all_last_names_masked(self):
        self.assertEqual(self.distinct(self.target, "people", "last_name"), [("Person Anonymous",)])

    def test_all_birth_dates_masked(self):
        self.assertEqual(self.distinct(self.target, "people", "birth_date"), [(dt.date(2000, 1, 1),)])

    def test_all_salaries_masked(self):
        self.assertEqual(self.distinct(self.target, "employment", "salary_eur"), [(3500,)])

    def test_all_company_profits_masked(self):
        self.assertEqual(self.distinct(self.target, "companies", "annual_profit_eur"), [(0,)])

    def test_verify_reports_zero_unmasked_and_no_orphans(self):
        result = mask.verify(self.target)
        self.assertEqual((result["total_unmasked_values"], result["orphaned_person_links"],
                          result["orphaned_company_links"]), (0, 0, 0))

    def test_rerun_changes_nothing(self):
        self.assertEqual(sum(mask.mask_pseudo_prod(self.target).values()), 0)

    def test_ids_and_tokens_preserved(self):
        query = "SELECT p.person_id, e.contract_id, e.company_id FROM business.people p " \
                "JOIN business.employment e ON e.employee_email = p.email ORDER BY 2"
        self.assertEqual(self.target.execute(query).fetchall(), self.source.execute(query).fetchall())
        tokens = self.target.execute("SELECT count(*) FROM business.people "
                                     "WHERE email LIKE 'tok-%%' AND national_id LIKE 'NID-%%'").fetchone()
        self.assertEqual(tokens, (1000,))

    def test_production_unchanged(self):
        self.assertEqual(self.source.execute("SELECT count(DISTINCT last_name) FROM business.people").fetchone(), (1000,))
        self.assertGreater(len(self.distinct(self.source, "employment", "salary_eur")), 1)

    def test_only_pseudo_prod_accepted(self):
        with self.psycopg.connect(os.environ["SOURCE_DSN"]) as production:
            with self.assertRaises(mask.MaskingError):
                mask.mask_pseudo_prod(production)
