"""Compare two schema description files from describe_schema.py.

Usage: python compare_schemas.py expected.schema.txt actual.schema.txt [--output schema.diff]

Exit codes: 0 = identical, 1 = different (diff printed and optionally saved), 2 = error.
"""

import argparse
import difflib
import sys
from pathlib import Path


def compare(expected_text, actual_text, expected_name="expected", actual_name="actual"):
    return "".join(difflib.unified_diff(
        expected_text.splitlines(keepends=True), actual_text.splitlines(keepends=True),
        fromfile=expected_name, tofile=actual_name))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("expected")
    parser.add_argument("actual")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        expected = Path(args.expected).read_text(encoding="utf-8")
        actual = Path(args.actual).read_text(encoding="utf-8")
    except OSError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2
    diff = compare(expected, actual, Path(args.expected).name, Path(args.actual).name)
    if args.output:
        Path(args.output).write_text(diff, encoding="utf-8")
    if not diff:
        print("Schemas match.")
        return 0
    print(diff, end="")
    print("Schemas differ.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
