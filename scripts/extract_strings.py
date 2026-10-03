#!/usr/bin/env python3
"""Collects the strings the Swift compiler marked as localizable (*.stringsdata) and prints
them as one JSON object, so translations can be checked against the exact keys in the code.

Usage: scripts/extract_strings.py <derived-data-dir> [Localizable.xcstrings]
With a catalog, also lists keys that are missing from it or no longer used.
"""
import json
import pathlib
import sys


def collect(root):
    keys = {}
    for path in pathlib.Path(root).rglob("*.stringsdata"):
        data = json.loads(path.read_text())
        for table, entries in data.get("tables", {}).items():
            if table != "Localizable":
                continue
            for entry in entries:
                key = entry["key"]
                keys.setdefault(key, set()).add(path.stem)
    return keys


def main():
    keys = collect(sys.argv[1])
    print(f"{len(keys)} localizable keys")
    if len(sys.argv) > 2:
        catalog = json.loads(pathlib.Path(sys.argv[2]).read_text())["strings"]
        missing = sorted(set(keys) - set(catalog))
        unused = sorted(set(catalog) - set(keys))
        untranslated = sorted(
            key for key, value in catalog.items()
            if key in keys and "de" not in value.get("localizations", {})
            and not value.get("shouldTranslate", True) is False
        )
        print(json.dumps({"missing": missing, "unused": unused, "untranslated": untranslated}, indent=1,
                         ensure_ascii=False))
        return 1 if missing or untranslated else 0
    print("BEGIN-KEYS")
    print(json.dumps(sorted(keys), ensure_ascii=False))
    print("END-KEYS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
