"""Presidio analyzer with Lithuanian recognisers added to the stock English ones."""

import os
import shutil
from pathlib import Path

# The email recogniser's suffix list was cached at build time (no internet at run time).
# The container root is read-only and tldextract needs a lock file, so use a writable copy.
_BUILD_CACHE = Path("/opt/presidio/tld-cache")
_RUN_CACHE = Path("/tmp/tld-cache")
if _BUILD_CACHE.exists() and not _RUN_CACHE.exists():
    shutil.copytree(_BUILD_CACHE, _RUN_CACHE)
if _RUN_CACHE.exists():
    os.environ["TLDEXTRACT_CACHE"] = str(_RUN_CACHE)

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

LT_NAME_CHARS = "A-ZĄČĘĖĮŠŲŪŽ"
LT_LOWER_CHARS = "a-ząčęėįšųūž"
NAME_WORD = f"[{LT_NAME_CHARS}][{LT_LOWER_CHARS}]+"


def lithuanian_recognizers():
    return [
        PatternRecognizer(
            supported_entity="LT_NATIONAL_ID", name="lt_national_id",
            patterns=[Pattern("lt asmens kodas", r"(?<!\d)[1-6]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}(?!\d)", 0.85)],
            context=["asmens", "kodas", "a.k.", "national", "id", "personal", "code"]),
        PatternRecognizer(
            supported_entity="LT_PHONE", name="lt_phone",
            patterns=[Pattern("lt mobile", r"(?<![\w+])(?:\+370[\s-]?|8[\s-]?|0)6\d(?:[\s-]?\d){6}(?!\w)", 0.75)],
            context=["tel", "telefonas", "phone", "mob"]),
        PatternRecognizer(
            supported_entity="LT_IBAN", name="lt_iban",
            patterns=[Pattern("lt iban", r"\bLT\d{2}(?:\s?\d{4}){4}\b", 0.9)]),
        PatternRecognizer(
            supported_entity="LT_ADDRESS", name="lt_address",
            patterns=[Pattern("lt street", rf"[{LT_NAME_CHARS}][\w\-ąčęėįšųūž]+\s(?:g|al|pr|pl|skg)\.\s?\d+[\w-]*(?:,\s?{NAME_WORD})?", 0.7)],
            context=["adresas", "address", "delivery", "gatvė"]),
        PatternRecognizer(
            supported_entity="EUR_AMOUNT", name="eur_amount",
            patterns=[Pattern("eur amount", r"(?<![\w.])\d[\d\s.,]*\s?(?:EUR|€)", 0.6)],
            context=["atlyginimas", "amount", "suma", "salary", "kaina"]),
        PatternRecognizer(
            supported_entity="LT_PERSON", name="lt_person_after_label",
            patterns=[Pattern("labelled lithuanian name",
                              rf"(?<=darbuotojas=|vardas=|vardas:\s|contact\s|klientas=)(?:{NAME_WORD})(?:\s{NAME_WORD})+", 0.8),
                      Pattern("name with lithuanian letters", rf"\b[{LT_NAME_CHARS}][\w]*[ąčęėįšųūž][\w]*\s{NAME_WORD}\b", 0.55)],
            context=["darbuotojas", "vardas", "pavardė", "klientas", "contact"]),
    ]


def build_analyzer():
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]})
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"])
    for recognizer in lithuanian_recognizers():
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(nlp_engine=provider.create_engine(), registry=registry, supported_languages=["en"])
