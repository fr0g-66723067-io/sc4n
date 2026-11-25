#!/usr/bin/env python3
"""Validate sc4n's SARIF output against the official SARIF 2.1.0 JSON Schema.

The scanner's Go test pins the requirements GitHub code scanning documents (rule
descriptors, levels, security-severity, primaryLocationLineHash). This script
pins the rest of the contract — URI-reference encoding, region bounds, enum
values, the schema version — against the schema the format actually defines.

It is the one place in the tree that needs a Python package
(`jsonschema`), because writing a JSON Schema validator is not a good use of a
scanner's standard library. `make sarif-check` skips loudly when the package is
absent, exactly like the optional differential check.

Usage: validate.py SCHEMA SARIF [SARIF ...]
Exit:  0 valid, 1 invalid, 2 usage or missing dependency.
"""

import json
import sys

try:
    import jsonschema
except ImportError:  # pragma: no cover - exercised by `make sarif-check`
    sys.stderr.write("sarifvalidate: python package 'jsonschema' is not installed\n")
    sys.exit(2)


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: validate.py SCHEMA SARIF [SARIF ...]\n")
        return 2
    schema = json.load(open(argv[1]))
    format_checker = getattr(jsonschema.Draft7Validator, "FORMAT_CHECKER", None)
    if format_checker is None:
        try:
            format_checker = jsonschema.FormatChecker()
        except Exception:
            format_checker = None
    validator = jsonschema.Draft7Validator(schema, format_checker=format_checker)
    # A SARIF log is a validator target, so resolve $ref against the schema we
    # were given rather than fetching it: the repository must validate offline.
    status = 0
    for path in argv[2:]:
        doc = json.load(open(path))
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        if errors:
            status = 1
            print("%s: %d schema violation(s)" % (path, len(errors)))
            for err in errors[:20]:
                where = "/".join(str(p) for p in err.absolute_path) or "(root)"
                print("  %s: %s" % (where, err.message))
            continue
        runs = doc.get("runs") or [{}]
        results = sum(len(run.get("results") or []) for run in runs)
        print("%s: valid SARIF 2.1.0 (%d result(s))" % (path, results))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
