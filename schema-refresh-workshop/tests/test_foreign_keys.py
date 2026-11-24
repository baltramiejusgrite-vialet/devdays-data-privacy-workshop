"""Exercise 2: tokenized pseudo-prod keeps every employment -> person connection.

Run inside the runner:
    docker compose run --rm refresh-runner python -m unittest discover -s tests -p test_foreign_keys.py -v

Every employment row has a person in production, so after tokenization each sampled
employment row must link to exactly one person in pseudo-prod, and to the same person
(by person_id) it linked to in production. Runs against pseudo-prod only.
"""

import os
import unittest

SAMPLE_SIZE = 200


@unittest.skipUnless(os.environ.get("PSEUDO_PROD_DSN") and os.environ.get("SOURCE_DSN"), "needs the runner container")
class EmploymentPersonLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        cls.target = psycopg.connect(os.environ["PSEUDO_PROD_DSN"], autocommit=True)
        cls.source = psycopg.connect(os.environ["SOURCE_DSN"], autocommit=True)
        cls.target.read_only = cls.source.read_only = True
        # Repeatable sample spread across the whole table.
        cls.sample = [r[0] for r in cls.target.execute(
            "SELECT contract_id FROM business.employment TABLESAMPLE BERNOULLI (50) REPEATABLE (42) "
            "ORDER BY contract_id LIMIT %s", (SAMPLE_SIZE,)).fetchall()]

    @classmethod
    def tearDownClass(cls):
        cls.target.close()
        cls.source.close()

    def test_database_is_pseudo_prod(self):
        self.assertEqual(self.target.execute("SELECT current_database()").fetchone(), ("pseudo-prod",))

    def test_sample_is_meaningful(self):
        self.assertGreaterEqual(len(self.sample), 100)

    def test_each_sampled_contract_has_exactly_one_person(self):
        rows = self.target.execute(
            "SELECT e.contract_id, count(p.person_id) FROM business.employment e "
            "LEFT JOIN business.people p ON p.email = e.employee_email "
            "WHERE e.contract_id = ANY(%s) GROUP BY e.contract_id", (self.sample,)).fetchall()
        self.assertEqual(len(rows), len(self.sample))
        self.assertEqual([cid for cid, people in rows if people != 1], [])

    def test_each_sampled_contract_links_to_the_same_person_as_in_production(self):
        query = ("SELECT e.contract_id, p.person_id FROM business.employment e "
                 "JOIN business.people p ON p.email = e.employee_email WHERE e.contract_id = ANY(%s)")
        source = dict(self.source.execute(query, (self.sample,)).fetchall())
        target = dict(self.target.execute(query, (self.sample,)).fetchall())
        self.assertEqual(target, source)

    def test_linking_values_are_tokens_not_originals(self):
        rows = self.target.execute(
            "SELECT count(*) FROM business.employment WHERE contract_id = ANY(%s) "
            "AND employee_email NOT LIKE 'tok-%%@pseudonym.invalid'", (self.sample,)).fetchone()
        self.assertEqual(rows, (0,))

    def test_no_contract_without_a_person_anywhere(self):
        orphans = self.target.execute(
            "SELECT count(*) FROM business.employment e WHERE NOT EXISTS "
            "(SELECT 1 FROM business.people p WHERE p.email = e.employee_email)").fetchone()
        self.assertEqual(orphans, (0,))

    def test_tokens_stay_unique_per_person(self):
        duplicates = self.target.execute(
            "SELECT count(*) FROM (SELECT email FROM business.people GROUP BY email HAVING count(*) > 1) d").fetchone()
        self.assertEqual(duplicates, (0,))
