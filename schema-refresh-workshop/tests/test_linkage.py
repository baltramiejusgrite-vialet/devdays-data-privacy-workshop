"""Record-linkage exercise tests. Run on the host from schema-refresh-workshop:
    python -m unittest discover -s tests -p test_linkage.py -v

Unit tests need nothing. The live test needs the database workshop on 127.0.0.1:5432 with
the pseudonymised privacy_pseudo database, and asserts that findings exist.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "linkage"))
import linkage_check as lc  # noqa: E402


def person(pid, city, postcode, employer, role):
    return {"person_id": pid, "city": city, "postcode": postcode, "employer": employer, "role": role,
            "first_name": "Person Anonymous", "date_of_birth": "2000-01-01"}


def profile(first, last, city, postcode, employer, role):
    return {"first_name": first, "last_name": last, "city": city, "postcode": postcode,
            "employer_name": employer, "role_title": role}


class FuzzyMatchingTests(unittest.TestCase):
    def test_normalise_ignores_case_diacritics_and_suffixes(self):
        self.assertEqual(lc.normalise("Šimkus Energy, UAB"), lc.normalise("simkus energy"))

    def test_postcode_key_ignores_format(self):
        self.assertEqual(lc.postcode_key("LT-62533"), lc.postcode_key("62533"))

    def test_near_match_is_found_not_only_exact(self):
        people = [person(1, "Vilnius", "LT-01665", "Zukauskas Retail UAB", "Legal Counsel")]
        public = [profile("Ona", "A", "VILNIUS", "01665", "Žukauskas Retail", "Legal counsel")]
        links = lc.link_profiles(people, public)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0][3], 1)

    def test_different_person_not_linked(self):
        people = [person(1, "Vilnius", "LT-01665", "Zukauskas Retail UAB", "Legal Counsel")]
        public = [profile("Ona", "A", "Vilnius", "LT-01665", "Banys Energy UAB", "Data Analyst")]
        self.assertEqual(lc.link_profiles(people, public), [])

    def test_ambiguous_match_reports_candidate_count(self):
        people = [person(1, "Vilnius", "LT-01665", "Zukauskas Retail UAB", "Legal Counsel")]
        public = [profile("Ona", "A", "Vilnius", "LT-01665", "Zukauskas Retail UAB", "Legal Counsel"),
                  profile("Jonas", "B", "Vilnius", "LT-01665", "Zukauskas Retail", "Legal Counsel")]
        self.assertEqual(lc.link_profiles(people, public)[0][3], 2)

    def test_company_linked_by_number_or_unique_name(self):
        companies = [{"registration_number": "CR1", "company_name": "A UAB"},
                     {"registration_number": "X", "company_name": "Banys Energy UAB"}]
        registry = [{"registration_number": "CR1", "company_name": "A UAB"},
                    {"registration_number": "CR2", "company_name": "BANYS ENERGY"}]
        self.assertEqual([how for _, _, how in lc.link_companies(companies, registry)],
                         ["registration number", "normalised name"])


class LiveLinkageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg

        try:
            psycopg.connect(lc.PSEUDO_DSN, connect_timeout=3).close()
        except psycopg.Error:
            raise unittest.SkipTest("privacy_pseudo on 127.0.0.1:5432 is not available")
        cls.result = lc.run(examples=0, output=Path("artifacts/linkage/findings.csv"))

    def test_there_are_findings(self):
        self.assertGreater(self.result["unique_profile"] + self.result["company_links"], 0)

    def test_people_re_identified_through_public_profiles(self):
        self.assertGreater(self.result["unique_profile"], 0)

    def test_masked_birth_dates_recovered_by_chaining(self):
        self.assertGreater(self.result["chained_birth_dates"], 0)

    def test_companies_linked_to_registry(self):
        self.assertGreater(self.result["company_links"], 0)
