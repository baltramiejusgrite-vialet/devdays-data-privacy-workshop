"""Look for record linkage between a pseudonymised database and the public-records database.

Usage (host, from schema-refresh-workshop, needs the database workshop running on :5432):
    python linkage/linkage_check.py                 # summary + 5 example findings per check
    python linkage/linkage_check.py --examples 20   # more examples
Full findings are written to artifacts/linkage/findings.csv (git-ignored).

Not exact joins: records are grouped by postcode, then city, employer and role are compared
with normalised fuzzy matching (case, diacritics, company suffixes, similarity ratio).
A pseudonymised record that fits exactly one public record is a likely re-identification.

Checks
  1. professional_profile  city + postcode + employer + role   -> name, profile URL, salary band
  2. people_directory      city + postcode (+ street area)      -> name and the masked birth date
  3. company_registry      registration number / company name  -> masked profit (as a band)
  4. k-anonymity of the quasi-identifiers left in the pseudonymised data

Prints the exact values of potential findings, as the exercise asks; the data is synthetic.
"""

import argparse
import csv
import os
import sys
import unicodedata
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path

import psycopg

PSEUDO_DSN = os.environ.get("PSEUDO_DSN", "postgresql://workshop:workshop@127.0.0.1:5432/privacy_pseudo")
PUBLIC_DSN = os.environ.get("PUBLIC_DSN", "postgresql://workshop:workshop@127.0.0.1:5432/privacy_workshop")
OUTPUT = Path("artifacts/linkage/findings.csv")
COMPANY_SUFFIXES = {"uab", "ab", "mb", "vsi", "ltd", "llc", "inc", "gmbh"}
THRESHOLD = 0.85


def normalise(text):
    text = unicodedata.normalize("NFKD", str(text or "")).encode("ascii", "ignore").decode().lower()
    words = "".join(ch if ch.isalnum() else " " for ch in text).split()
    return " ".join(w for w in words if w not in COMPANY_SUFFIXES)


def similarity(a, b):
    a, b = normalise(a), normalise(b)
    if not a or not b:
        return 0.0
    return 1.0 if a == b else SequenceMatcher(None, a, b).ratio()


def postcode_key(postcode):
    return "".join(ch for ch in str(postcode or "") if ch.isdigit())


def score_profile(person, profile):
    """Average fuzzy similarity of city, employer and role (postcode already matched)."""
    return (similarity(person["city"], profile["city"]) + similarity(person["employer"], profile["employer_name"])
            + similarity(person["role"], profile["role_title"])) / 3


def link_profiles(people, profiles, threshold=THRESHOLD):
    """[(person, best_profile, score, candidate_count)] for people with at least one candidate."""
    by_postcode = defaultdict(list)
    for profile in profiles:
        by_postcode[postcode_key(profile["postcode"])].append(profile)
    findings = []
    for person in people:
        scored = [(score_profile(person, p), p) for p in by_postcode.get(postcode_key(person["postcode"]), [])]
        candidates = [(s, p) for s, p in scored if s >= threshold]
        if candidates:
            score, best = max(candidates, key=lambda item: item[0])
            findings.append((person, best, score, len(candidates)))
    return findings


def link_directory(people, directory):
    by_area = defaultdict(list)
    for entry in directory:
        by_area[(postcode_key(entry["postcode"]), normalise(entry["city"]))].append(entry)
    return [(person, by_area[key][0], len(by_area[key])) for person in people
            if len(by_area.get(key := (postcode_key(person["postcode"]), normalise(person["city"])), [])) >= 1]


def chain_birth_dates(profile_links, directory):
    """Re-identified name + postcode from check 1 -> people_directory -> the real (masked) birth date."""
    by_name_area = defaultdict(list)
    for entry in directory:
        by_name_area[(normalise(entry["first_name"]), normalise(entry["last_name"]),
                      postcode_key(entry["postcode"]))].append(entry)
    chained = []
    for person, profile, score, n in profile_links:
        if n != 1:
            continue
        entries = by_name_area.get((normalise(profile["first_name"]), normalise(profile["last_name"]),
                                    postcode_key(person["postcode"])), [])
        if len(entries) == 1:
            chained.append((person, profile, entries[0]))
    return chained


def link_companies(companies, registry):
    by_number = {r["registration_number"]: r for r in registry}
    by_name = defaultdict(list)
    for r in registry:
        by_name[normalise(r["company_name"])].append(r)
    findings = []
    for company in companies:
        match = by_number.get(company["registration_number"])
        how = "registration number"
        if match is None and len(by_name.get(normalise(company["company_name"]), [])) == 1:
            match, how = by_name[normalise(company["company_name"])][0], "normalised name"
        if match:
            findings.append((company, match, how))
    return findings


def fetch(conn, query):
    with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        return cur.execute(query).fetchall()


def load(pseudo_dsn, public_dsn):
    with psycopg.connect(pseudo_dsn) as pseudo, psycopg.connect(public_dsn) as public:
        pseudo.read_only = public.read_only = True
        people = fetch(pseudo, """
            SELECT p.person_id, p.first_name, p.date_of_birth, p.home_city AS city, p.home_postcode AS postcode,
                   p.home_street AS street, c.company_name AS employer, e.role_title AS role, e.department,
                   e.salary_eur
            FROM private_db.person_identity p
            JOIN private_db.employment_contract e ON e.national_id = p.national_id
            JOIN private_db.company c ON c.registration_number = e.company_registration_number""")
        companies = fetch(pseudo, "SELECT registration_number, company_name, industry, headquarters_city, "
                                  "annual_profit_eur FROM private_db.company")
        profiles = fetch(public, "SELECT first_name, last_name, city, postcode, employer_name, role_title, "
                                 "seniority, salary_band, public_profile_url FROM public_db.professional_profile")
        directory = fetch(public, "SELECT first_name, last_name, date_of_birth, city, postcode, public_profile_url "
                                  "FROM public_db.people_directory")
        registry = fetch(public, "SELECT registration_number, company_name, industry, city, profit_band, revenue_band "
                                 "FROM public_db.company_registry")
    return people, companies, profiles, directory, registry


def k_anonymity(people):
    groups = Counter((normalise(p["city"]), postcode_key(p["postcode"]), normalise(p["employer"]), normalise(p["role"]))
                     for p in people)
    unique = sum(1 for p in people if groups[(normalise(p["city"]), postcode_key(p["postcode"]),
                                              normalise(p["employer"]), normalise(p["role"]))] == 1)
    return unique, len(groups)


def run(pseudo_dsn=PSEUDO_DSN, public_dsn=PUBLIC_DSN, examples=5, output=OUTPUT):
    people, companies, profiles, directory, registry = load(pseudo_dsn, public_dsn)
    profile_links = link_profiles(people, profiles)
    unique_profile = [f for f in profile_links if f[3] == 1]
    directory_links = link_directory(people, directory)
    unique_directory = [f for f in directory_links if f[2] == 1]
    chained = chain_birth_dates(profile_links, directory)
    company_links = link_companies(companies, registry)
    unique_qi, groups = k_anonymity(people)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["check", "pseudonymised_record", "matched_on", "public_record", "revealed", "candidates", "score"])
        for person, profile, score, n in profile_links:
            writer.writerow(["professional_profile", person["person_id"],
                             f"{person['city']} {person['postcode']} | {person['employer']} | {person['role']}",
                             f"{profile['first_name']} {profile['last_name']} {profile['public_profile_url']}",
                             f"salary_band={profile['salary_band']}", n, f"{score:.2f}"])
        for person, entry, n in directory_links:
            writer.writerow(["people_directory", person["person_id"], f"{person['city']} {person['postcode']}",
                             f"{entry['first_name']} {entry['last_name']}", f"date_of_birth={entry['date_of_birth']}", n, ""])
        for person, profile, entry in chained:
            writer.writerow(["profile_then_directory", person["person_id"],
                             f"{profile['first_name']} {profile['last_name']} {person['postcode']}",
                             entry["public_profile_url"], f"date_of_birth={entry['date_of_birth']}", 1, ""])
        for company, match, how in company_links:
            writer.writerow(["company_registry", company["registration_number"], how, match["company_name"],
                             f"profit_band={match['profit_band']} (pseudonymised profit={company['annual_profit_eur']})",
                             1, ""])

    print(f"Pseudonymised records: {len(people)} people, {len(companies)} companies")
    print(f"Public records: {len(profiles)} profiles, {len(directory)} directory entries, {len(registry)} companies\n")

    print(f"1. professional_profile: {len(profile_links)} people have a fuzzy match "
          f"(score >= {THRESHOLD}); {len(unique_profile)} match exactly one public profile (re-identified)")
    for person, profile, score, n in unique_profile[:examples]:
        print(f"   person_id={person['person_id']} [{person['first_name']}, salary {person['salary_eur']}] "
              f"{person['city']} {person['postcode']} | {person['employer']} | {person['role']}\n"
              f"     -> {profile['first_name']} {profile['last_name']}, {profile['city']} {profile['postcode']}, "
              f"{profile['employer_name']}, {profile['role_title']} ({profile['seniority']}), "
              f"salary band {profile['salary_band']}, {profile['public_profile_url']}  score={score:.2f}")

    print(f"\n2. people_directory: {len(directory_links)} people share city+postcode with directory entries; "
          f"{len(unique_directory)} share it with exactly one (name and real birth date recovered)")
    for person, entry, n in unique_directory[:examples]:
        print(f"   person_id={person['person_id']} [{person['first_name']}, born {person['date_of_birth']}] "
              f"{person['city']} {person['postcode']}, {person['street']}\n"
              f"     -> {entry['first_name']} {entry['last_name']}, born {entry['date_of_birth']}, "
              f"{entry['public_profile_url']}")
    print(f"   chained (check 1 name + postcode -> directory): {len(chained)} people's real birth date recovered")
    for person, profile, entry in chained[:examples]:
        print(f"   person_id={person['person_id']} [born {person['date_of_birth']}] -> "
              f"{entry['first_name']} {entry['last_name']}, {person['postcode']}, born {entry['date_of_birth']}")

    print(f"\n3. company_registry: {len(company_links)} of {len(companies)} companies linked; masked profit "
          f"recovered as a band")
    for company, match, how in company_links[:examples]:
        print(f"   {company['registration_number']} {company['company_name']} [profit {company['annual_profit_eur']}] "
              f"--{how}--> {match['company_name']}, {match['industry']}, {match['city']}, "
              f"profit band {match['profit_band']}, revenue band {match['revenue_band']}")

    print(f"\n4. k-anonymity: {unique_qi} of {len(people)} pseudonymised people are unique on "
          f"(city, postcode, employer, role) across {groups} groups")
    print(f"\nAll findings: {output}")
    total = len(unique_profile) + len(unique_directory) + len(company_links)
    print(f"RESULT: {total} potential record linkages found" if total else "RESULT: no record linkages found")
    return {"profile_links": len(profile_links), "unique_profile": len(unique_profile),
            "directory_links": len(directory_links), "unique_directory": len(unique_directory),
            "chained_birth_dates": len(chained),
            "company_links": len(company_links), "unique_quasi_identifiers": unique_qi, "people": len(people)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--examples", type=int, default=5)
    parser.add_argument("--pseudo-dsn", default=PSEUDO_DSN)
    parser.add_argument("--public-dsn", default=PUBLIC_DSN)
    args = parser.parse_args()
    run(args.pseudo_dsn, args.public_dsn, args.examples)
    return 0


if __name__ == "__main__":
    sys.exit(main())
