#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks that every *.json file in a directory is valid JSON with the expected schema id."""

import json
import sys
from pathlib import Path


def main() -> int:
    directory = Path(sys.argv[1])
    files = sorted(directory.glob("*.json"))
    if not files:
        print(f"error: no JSON files in {directory}", file=sys.stderr)
        return 1
    for f in files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        if doc.get("schema") != "wifi-analyze.decoded" or doc.get("schema_version") != 1:
            print(f"error: {f}: unexpected schema", file=sys.stderr)
            return 1
        for key in ("summary", "overview", "elements", "diagnostics"):
            if key not in doc:
                print(f"error: {f}: missing '{key}'", file=sys.stderr)
                return 1
    print(f"{len(files)} files OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
