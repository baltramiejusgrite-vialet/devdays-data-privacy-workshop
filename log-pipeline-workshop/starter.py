"""Log sanitiser: read one batch of raw JSON logs, print sanitised JSON Lines.

Run: docker compose -f log-pipeline-workshop/docker-compose.yml run --rm processor

Reads up to BATCH_SIZE lines (default 100) from each of /raw/hr/app.jsonl and
/raw/billing/app.jsonl. Source files are opened read-only and never modified.

  * Operational fields (level, event, sequence, timestamps, ids of the log itself) are kept.
  * Fields whose names are personal or financial are replaced with "[REDACTED:<kind>]",
    at any depth, including inside lists.
  * Free text (messages and any unknown string) is scrubbed: first every sensitive value
    found elsewhere in the same record, then patterns for Lithuanian national IDs, phones,
    emails, IBANs, EUR amounts, street addresses and "key=value" pairs with sensitive keys.
  * Malformed lines are skipped; only their count and line numbers are reported (to stderr),
    never their content.
"""

import json
import os
import re
import sys
import unicodedata
from pathlib import Path

SOURCES = {"hr": Path("/raw/hr/app.jsonl"), "billing": Path("/raw/billing/app.jsonl")}
OPERATIONAL_FIELDS = {"level", "event", "sequence", "timestamp", "time", "ts", "service", "request_id", "trace_id"}

# Field-name fragments (accent-free, lower case) -> redaction kind.
SENSITIVE_NAME_PARTS = [
    ("national_id", "national_id"), ("personal_code", "national_id"), ("asmens_kodas", "national_id"),
    ("email", "email"), ("e_mail", "email"), ("el_pastas", "email"), ("contacts", "email"),
    ("phone", "phone"), ("telefon", "phone"), ("mobile", "phone"),
    ("address", "address"), ("adresas", "address"), ("street", "address"),
    ("iban", "bank_account"), ("bank_account", "bank_account"), ("card", "card"),
    ("salary", "financial"), ("atlyginimas", "financial"), ("profit", "financial"), ("amount", "financial"),
    ("price", "financial"), ("revenue", "financial"), ("_eur", "financial"),
    ("name", "name"), ("darbuotojas", "name"), ("employee", "name"), ("customer", "name"), ("person", "name"),
    ("birth", "birth_date"), ("password", "secret"), ("token", "secret"), ("secret", "secret"),
]

PATTERNS = [
    ("email", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("bank_account", re.compile(r"\bLT\d{2}(?:\s?\d{4}){4}\b", re.I)),
    ("national_id", re.compile(r"(?<!\d)[1-6]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}(?!\d)")),
    ("phone", re.compile(r"(?<![\w])(?:\+370[\s-]?|8[\s-]?|0)6\d(?:[\s-]?\d){6}(?![\w])")),
    ("financial", re.compile(r"(?<![\w.])\d[\d\s.,]*\s?(?:EUR|eur|€)")),
    ("address", re.compile(r"[\wÀ-ž]+(?:\s[\wÀ-ž]+)?\s(?:g|al|pr|pl|skg)\.\s?\d+[\w-]*(?:,\s?[\wÀ-ž]+)?")),
]
KEY_VALUE = re.compile(r"(?P<key>[\wÀ-ž]+)\s*(?P<sep>[=:])\s*(?P<value>[^;,\n]+)")


def plain(name):
    return unicodedata.normalize("NFKD", str(name)).encode("ascii", "ignore").decode().lower()


def sensitive_kind(field_name):
    name = plain(field_name)
    if name in OPERATIONAL_FIELDS:
        return None
    for part, kind in SENSITIVE_NAME_PARTS:
        if part in name:
            return kind
    return None


def redacted(kind):
    return f"[REDACTED:{kind}]"


def collect_sensitive_values(value, inherited=None, found=None):
    """Every string/number held under a sensitive field name anywhere in the record."""
    found = set() if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            collect_sensitive_values(item, sensitive_kind(key) or inherited, found)
    elif isinstance(value, list):
        for item in value:
            collect_sensitive_values(item, inherited, found)
    elif inherited and isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value).strip()
        if len(text) >= 3:
            found.add(text)
    return found


def scrub_text(text, known_values=()):
    for value in sorted(known_values, key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")

    def key_value(match):
        kind = sensitive_kind(match.group("key"))
        if kind:
            return f"{match.group('key')}{match.group('sep')}{redacted(kind)}"
        return match.group(0)

    text = KEY_VALUE.sub(key_value, text)
    for kind, pattern in PATTERNS:
        text = pattern.sub(redacted(kind), text)
    return text


def sanitise_value(value, known_values, kind=None):
    """Sensitive field: dicts keep their keys (each sanitised), anything else is replaced."""
    if kind and not isinstance(value, dict):
        if isinstance(value, list) and any(isinstance(i, (dict, list)) for i in value):
            return [sanitise_value(item, known_values, kind) for item in value]
        return redacted(kind)
    if isinstance(value, dict):
        return {key: sanitise_value(item, known_values, sensitive_kind(key) or kind) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitise_value(item, known_values) for item in value]
    if isinstance(value, str):
        return scrub_text(value, known_values)
    return value


def sanitise_record(record, service):
    known = collect_sensitive_values(record)
    clean = {"service": service}
    for key, value in record.items():
        if key in OPERATIONAL_FIELDS:
            clean[key] = value if not isinstance(value, str) else scrub_text(value, known)
        else:
            clean[key] = sanitise_value(value, known, sensitive_kind(key))
    return clean


def read_batch(path, batch_size):
    """Yields (line_number, record or None) for up to batch_size lines; None means malformed."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if number > batch_size:
                break
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                yield number, None
                continue
            yield number, record if isinstance(record, dict) else None


def process(sources=SOURCES, batch_size=100, out=sys.stdout, err=sys.stderr):
    printed, skipped = 0, []
    for service, path in sources.items():
        for number, record in read_batch(path, batch_size):
            if record is None:
                skipped.append(f"{service}:{number}")
                continue
            out.write(json.dumps(sanitise_record(record, service), ensure_ascii=False) + "\n")
            printed += 1
    if skipped:
        err.write(f"skipped {len(skipped)} malformed record(s) at {', '.join(skipped)}; contents not shown\n")
    err.write(f"sanitised {printed} record(s)\n")
    return printed, len(skipped)


def main():
    process(batch_size=int(os.environ.get("BATCH_SIZE", "100")))


if __name__ == "__main__":
    main()
