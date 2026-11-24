"""Exercise 4, step 1: the schema description is complete, sorted and reproducible.

Run inside the runner:
    docker compose run --rm refresh-runner python -m unittest discover -s tests -p test_schema_description.py -v
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from describe_schema import read_schema, render_schema  # noqa: E402

EXPECTED_TABLES = ["business.companies", "business.employment", "business.people"]


class RenderTests(unittest.TestCase):
    def test_render_format(self):
        text = render_schema({"s.a": [("id", "bigint not null"), ("name", "text")]})
        self.assertEqual(text, "table s.a\n  id: bigint not null\n  name: text\n")


@unittest.skipUnless(os.environ.get("PSEUDO_PROD_DSN"), "needs the runner container")
class SchemaDescriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        cls.conn = psycopg.connect(os.environ["PSEUDO_PROD_DSN"], autocommit=True)
        cls.schema = read_schema(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_lists_business_tables(self):
        self.assertEqual([t for t in self.schema if t.startswith("business.")], EXPECTED_TABLES)

    def test_tables_and_columns_sorted_alphabetically(self):
        self.assertEqual(list(self.schema), sorted(self.schema))
        for table, columns in self.schema.items():
            with self.subTest(table=table):
                self.assertEqual(columns, sorted(columns))

    def test_known_columns_and_types(self):
        people = dict(self.schema["business.people"])
        self.assertEqual(people["email"], "text not null")
        self.assertEqual(people["birth_date"], "date not null")
        self.assertEqual(people["person_id"], "bigint not null")
        self.assertEqual(dict(self.schema["business.employment"])["salary_eur"], "integer not null")

    def test_repeated_generation_identical(self):
        self.assertEqual(render_schema(read_schema(self.conn)), render_schema(self.schema))

    def test_no_row_values_in_description(self):
        text = render_schema(self.schema)
        self.assertNotIn("Person Anonymous", text)
        self.assertNotIn("tok-", text)
