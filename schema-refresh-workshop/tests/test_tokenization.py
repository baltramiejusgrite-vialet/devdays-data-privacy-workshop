"""Tests for tokenize_pseudo_prod.py. Run inside the runner:

    docker compose run --rm refresh-runner python -m unittest discover -s tests -p test_tokenization.py -v

Unit tests need nothing; integration tests use SOURCE_DSN (read-only production) and
PSEUDO_PROD_DSN and expect pseudo-prod to have been tokenized. No key or original value
is printed.
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tokenize_pseudo_prod as tok  # noqa: E402

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


class TokenUnitTests(unittest.TestCase):
    def test_same_input_same_token(self):
        self.assertEqual(tok.token(KEY, "email", "a@example.com"), tok.token(KEY, "email", "a@example.com"))

    def test_different_key_different_token(self):
        self.assertNotEqual(tok.token(KEY, "email", "a@example.com"), tok.token(OTHER_KEY, "email", "a@example.com"))

    def test_kinds_are_separated(self):
        email = tok.token(KEY, "email", "39000000001")
        nid = tok.token(KEY, "national_id", "39000000001")
        self.assertNotEqual(email.split("@")[0].removeprefix("tok-"), nid.removeprefix("NID-"))

    def test_token_hides_value(self):
        value = "person-42@example.com"
        self.assertNotIn("person-42", tok.token(KEY, "email", value))
        self.assertNotIn("39000000042", tok.token(KEY, "national_id", "39000000042"))

    def test_token_is_full_hmac_sha256(self):
        self.assertRegex(tok.token(KEY, "email", "x"), r"^tok-[0-9a-f]{64}@pseudonym\.invalid$")
        self.assertRegex(tok.token(KEY, "national_id", "x"), r"^NID-[0-9a-f]{64}$")

    def test_column_names_classified(self):
        for name, kind in [("email", "email"), ("employee_email", "email"), ("emergency_contact_email", "email"),
                           ("E_Mail", "email"), ("national_id", "national_id"), ("nationalid", "national_id"),
                           ("first_name", None), ("phone", None), ("favorite_color", None)]:
            with self.subTest(name=name):
                self.assertEqual(tok.kind_for(name), kind)

    def test_null_stays_null(self):
        self.assertIsNone(tok.expected_value(KEY, "email", "text", None))
        self.assertIsNone(tok.expected_value(KEY, None, "jsonb", None))

    def test_nested_json_identifiers_tokenized(self):
        payload = {"delivery": {"email": "delivery-secret@example.com", "phone": "0612 34 567"},
                   "contacts": [{"national_id": "39000000007"}], "note": "keep"}
        result = tok.tokenize_json(KEY, payload)
        self.assertEqual(result["delivery"]["email"], tok.token(KEY, "email", "delivery-secret@example.com"))
        self.assertEqual(result["contacts"][0]["national_id"], tok.token(KEY, "national_id", "39000000007"))
        self.assertEqual(result["delivery"]["phone"], "0612 34 567")
        self.assertEqual(result["note"], "keep")
        self.assertEqual([v for _, v in tok.json_identifiers(payload)],
                         ["delivery-secret@example.com", "39000000007"])
        self.assertNotIn("delivery-secret", str(result))

    def test_key_created_32_bytes_mode_0600_and_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "keys" / "k"
            first = tok.load_or_create_key(path)
            self.assertEqual(len(first), 32)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(tok.load_or_create_key(path), first)

    def test_wrong_size_key_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "k"
            path.write_bytes(b"short")
            with self.assertRaises(tok.TokenizationError):
                tok.load_or_create_key(path)


@unittest.skipUnless(os.environ.get("PSEUDO_PROD_DSN") and os.environ.get("SOURCE_DSN"), "needs the runner container")
class PseudoProdIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        cls.psycopg = psycopg
        cls.key = tok.load_or_create_key()
        cls.source_dsn = os.environ["SOURCE_DSN"]
        cls.target_dsn = os.environ["PSEUDO_PROD_DSN"]

    def query(self, dsn, text, params=()):
        with self.psycopg.connect(dsn) as conn:
            return conn.execute(text, params).fetchall()

    def snapshot(self):
        return self.query(self.target_dsn,
                          "SELECT p.person_id, p.email, p.national_id, e.contract_id, e.employee_email "
                          "FROM business.people p LEFT JOIN business.employment e ON e.employee_email = p.email "
                          "ORDER BY 1, 4")

    def test_zero_non_keyed_values(self):
        result = tok.verify(self.source_dsn, self.target_dsn, self.key)
        self.assertGreater(result["checked_values"], 0)
        self.assertEqual(result["non_keyed_values"], 0)

    def test_no_original_values_remain(self):
        self.assertEqual(tok.verify(self.source_dsn, self.target_dsn, self.key)["remaining_original_values"], 0)

    def test_no_original_email_or_national_id_matches_exactly(self):
        source_emails = {r[0] for r in self.query(self.source_dsn, "SELECT email FROM business.people")}
        source_ids = {r[0] for r in self.query(self.source_dsn, "SELECT national_id FROM business.people")}
        target = self.query(self.target_dsn, "SELECT email, national_id FROM business.people "
                                             "UNION ALL SELECT employee_email, NULL FROM business.employment")
        self.assertEqual([r for r in target if r[0] in source_emails or r[1] in source_ids], [])

    def test_no_example_com_addresses_left_anywhere(self):
        rows = self.query(self.target_dsn,
                          "SELECT count(*) FROM business.people WHERE email LIKE '%%@example.com' "
                          "OR national_id ~ '^[0-9]+$'")
        self.assertEqual(rows, [(0,)])
        rows = self.query(self.target_dsn, "SELECT count(*) FROM business.employment WHERE employee_email LIKE '%%@example.com'")
        self.assertEqual(rows, [(0,)])

    def test_every_value_is_this_keys_hmac_of_its_own_source_row(self):
        source = dict(self.query(self.source_dsn, "SELECT person_id, email FROM business.people"))
        target = dict(self.query(self.target_dsn, "SELECT person_id, email FROM business.people"))
        self.assertEqual(target, {pid: tok.token(self.key, "email", raw) for pid, raw in source.items()})

    def test_employment_join_preserved(self):
        self.assertEqual(tok.verify(self.source_dsn, self.target_dsn, self.key)["orphaned_employment_links"], 0)
        source_join = self.query(self.source_dsn, "SELECT count(*) FROM business.employment e "
                                                  "JOIN business.people p ON p.email = e.employee_email")
        target_join = self.query(self.target_dsn, "SELECT count(*) FROM business.employment e "
                                                  "JOIN business.people p ON p.email = e.employee_email")
        self.assertEqual(target_join, source_join)

    def test_row_counts_unchanged(self):
        for table in ("people", "employment", "companies"):
            with self.subTest(table=table):
                self.assertEqual(self.query(self.target_dsn, f"SELECT count(*) FROM business.{table}"),
                                 self.query(self.source_dsn, f"SELECT count(*) FROM business.{table}"))

    def test_source_is_untouched(self):
        rows = self.query(self.source_dsn, "SELECT count(*) FROM business.people "
                                           "WHERE email LIKE 'person-%%@example.com' AND national_id ~ '^390[0-9]{8}$'")
        self.assertEqual(rows, [(1000,)])

    def test_source_login_cannot_write(self):
        with self.assertRaises(self.psycopg.errors.InsufficientPrivilege):
            self.query(self.source_dsn, "UPDATE business.people SET email = email WHERE person_id = 1")

    def test_rerun_with_same_key_is_stable(self):
        before = self.snapshot()
        self.assertEqual(tok.tokenize(self.source_dsn, self.target_dsn, self.key)["updated_values"], 0)
        self.assertEqual(self.snapshot(), before)

    def test_different_key_rejected_and_nothing_changes(self):
        before = self.snapshot()
        with self.assertRaises(tok.TokenizationError):
            tok.tokenize(self.source_dsn, self.target_dsn, OTHER_KEY)
        self.assertEqual(self.snapshot(), before)
        self.assertNotEqual(tok.verify(self.source_dsn, self.target_dsn, OTHER_KEY)["non_keyed_values"], 0)

    def test_foreign_keys_still_enforced(self):
        with self.psycopg.connect(self.target_dsn) as conn:
            self.assertEqual(conn.execute("SHOW session_replication_role").fetchone(), ("origin",))
            with self.assertRaises(self.psycopg.errors.ForeignKeyViolation):
                with conn.transaction():
                    conn.execute("INSERT INTO business.employment VALUES (999999, 'nobody@example.com', 1, 1, 'X')")

    def test_key_file_protected_and_not_in_database(self):
        self.assertEqual(stat.S_IMODE(tok.KEY_FILE.stat().st_mode), 0o600)
        dump = self.query(self.target_dsn, "SELECT string_agg(t::text, '') FROM business.people t")[0][0]
        self.assertNotIn(self.key.hex(), dump)
