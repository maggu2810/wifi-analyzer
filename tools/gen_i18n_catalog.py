#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile libwifianalyze domain messages into C++ tables.

Messages are defined where they are used, in C++ sources:

    WA_TR(rsn_group_cipher, "Group Cipher")

The first argument is the stable message key (also used as JSON field key), the second the
English text (adjacent string literals are concatenated). Positional placeholders {0}, {1}, ...
may be used. The same key may appear several times but always with the same text.

Translations are gettext <locale>.po files: msgctxt = key, msgid = English text, msgstr =
translation. An empty msgstr means "not translated" (English fallback at runtime). A
translation whose msgid no longer matches the English text is ignored with a warning.

Outputs:
  <out>/include/wifi_analyze/message_id.hpp   enum class MessageId
  <out>/i18n_catalog.inc                      constexpr tables (included by src/i18n/)
  <out>/messages.pot                          template for translators
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
LOCALE_RE = re.compile(r"^[a-z]{2,3}(_[A-Z]{2})?$")
PLACEHOLDER_RE = re.compile(r"(?<!\{)\{(\d+)\}(?!\})")
CXX_LITERAL = r'"(?:[^"\\\n]|\\.)*"'
WA_TR_RE = re.compile(r"\bWA_TR\(\s*([A-Za-z0-9_]+)\s*,\s*((?:" + CXX_LITERAL + r"\s*)+)\)")
SOURCE_SUFFIXES = {".cpp", ".hpp", ".h", ".cc"}


class CatalogError(Exception):
    pass


@dataclass
class Entry:
    key: str
    msgid: str
    msgstr: str
    where: str


def unescape(s: str, where: str) -> str:
    out = []
    i = 0
    mapping = {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "'": "'"}
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 1
            if i >= len(s) or s[i] not in mapping:
                raise CatalogError(f"{where}: unsupported escape sequence")
            out.append(mapping[s[i]])
        else:
            out.append(c)
        i += 1
    return "".join(out)


def extract_sources(paths: list[Path]) -> list[Entry]:
    """Collects WA_TR(key, "text") uses from C++ sources (files or directories)."""
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.suffix in SOURCE_SUFFIXES)
        else:
            files.append(p)
    found: dict[str, Entry] = {}
    for f in files:
        text = f.read_text(encoding="utf-8")
        for m in WA_TR_RE.finditer(text):
            key = m.group(1)
            line = text.count("\n", 0, m.start()) + 1
            where = f"{f}:{line}"
            if not KEY_RE.match(key):
                raise CatalogError(f"{where}: invalid message key {key!r} (use snake_case)")
            literals = re.findall(CXX_LITERAL, m.group(2))
            msgid = "".join(unescape(lit[1:-1], where) for lit in literals)
            if not msgid:
                raise CatalogError(f"{where}: empty English text for {key!r}")
            prev = found.get(key)
            if prev and prev.msgid != msgid:
                raise CatalogError(
                    f"{where}: key {key!r} redefined with different text (first at {prev.where})")
            if not prev:
                found[key] = Entry(key, msgid, "", where)
    return sorted(found.values(), key=lambda e: e.key)


def parse_po(path: Path) -> list[Entry]:
    """Minimal .po parser: msgctxt/msgid/msgstr with continuation lines."""
    entries: list[Entry] = []
    current: dict[str, str] = {}
    field_name: str | None = None
    start_line = 0

    def flush() -> None:
        nonlocal current, field_name
        if current:
            if "msgid" not in current or "msgstr" not in current:
                raise CatalogError(f"{path}:{start_line}: incomplete entry")
            key = current.get("msgctxt")
            if key is None:
                if current["msgid"] != "":  # only the header entry may lack a context
                    raise CatalogError(f"{path}:{start_line}: entry without msgctxt key")
            else:
                entries.append(Entry(key, current["msgid"], current["msgstr"],
                                     f"{path}:{start_line}"))
        current = {}
        field_name = None

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            flush()
            continue
        m = re.match(r'^(msgctxt|msgid|msgstr)\s+"(.*)"$', line)
        if m:
            name, value = m.group(1), m.group(2)
            if name in current:
                flush()
            if not current:
                start_line = lineno
            current[name] = unescape(value, f"{path}:{lineno}")
            field_name = name
            continue
        m = re.match(r'^"(.*)"$', line)
        if m and field_name:
            current[field_name] += unescape(m.group(1), f"{path}:{lineno}")
            continue
        raise CatalogError(f"{path}:{lineno}: cannot parse line: {raw!r}")
    flush()
    return entries


def placeholders(text: str) -> set[int]:
    return {int(n) for n in PLACEHOLDER_RE.findall(text)}


def load_translation(po: Path, source: dict[str, Entry]) -> dict[str, str]:
    result: dict[str, str] = {}
    for e in parse_po(po):
        src = source.get(e.key)
        if src is None:
            print(f"warning: {e.where}: key {e.key!r} is not used anymore (ignored)",
                  file=sys.stderr)
            continue
        if not e.msgstr:
            continue
        if e.msgid != src.msgid:
            print(f"warning: {e.where}: {e.key!r} translates an outdated English text "
                  "(ignored, falls back to English)", file=sys.stderr)
            continue
        if placeholders(e.msgstr) != placeholders(src.msgid):
            raise CatalogError(f"{e.where}: placeholders of {e.key!r} differ from the source")
        result[e.key] = e.msgstr
    return result


def po_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def cxx_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8")


def generate(sources: list[Path], pos: list[Path], out: Path) -> None:
    entries = extract_sources(sources)
    if not entries:
        raise CatalogError("no WA_TR(...) messages found in the sources")
    source = {e.key: e for e in entries}

    locales: list[tuple[str, dict[str, str]]] = [("en", {e.key: e.msgid for e in entries})]
    for po in sorted(pos):
        locale = po.stem
        if not LOCALE_RE.match(locale) or locale == "en":
            raise CatalogError(f"{po}: file name must be a locale like 'de' or 'pt_BR'")
        locales.append((locale, load_translation(po, source)))

    hdr = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by tools/gen_i18n_catalog.py from WA_TR() uses – do not edit.",
        "#pragma once",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "namespace wifi_analyze {",
        "",
        "/// Identifier of a translatable domain message (see docs/i18n.md).",
        "enum class MessageId : std::uint16_t {",
    ]
    hdr += [f"    {e.key}," for e in entries]
    hdr += [
        "};",
        "",
        f"inline constexpr std::size_t message_count = {len(entries)};",
        "",
        "} // namespace wifi_analyze",
        "",
    ]

    n = len(entries)
    inc = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by tools/gen_i18n_catalog.py – do not edit.",
        "// Included by src/i18n/catalog.cpp only.",
        "",
        f"inline constexpr std::array<std::string_view, {n}> message_keys{{{{",
    ]
    inc += [f"    {cxx_string(e.key)}," for e in entries]
    inc += ["}};", ""]
    for locale, texts in locales:
        # Double braces: a leading "{}" entry must not be taken for the inner array.
        inc.append(f"inline constexpr std::array<std::string_view, {n}> catalog_{locale}{{{{")
        for e in entries:
            text = texts.get(e.key)
            inc.append(f"    {cxx_string(text)}," if text else "    {},")
        inc += ["}};", ""]
    inc.append(f"inline constexpr std::array<LocaleCatalog, {len(locales)}> catalogs{{{{")
    for locale, _ in locales:
        inc.append(f"    {{.locale = {cxx_string(locale)}, .texts = &catalog_{locale}}},")
    inc += ["}};", ""]

    pot = [
        "# libwifianalyze domain messages – generated template, do not edit.",
        "# Copy entries into <locale>.po in libs/wifi-analyze/i18n/ and fill msgstr.",
        'msgid ""',
        'msgstr ""',
        '"Content-Type: text/plain; charset=UTF-8\\n"',
        "",
    ]
    for e in entries:
        pot += [f"#: {e.where.split('/src/')[-1]}", f"msgctxt {po_string(e.key)}",
                f"msgid {po_string(e.msgid)}", 'msgstr ""', ""]

    write_if_changed(out / "include" / "wifi_analyze" / "message_id.hpp", "\n".join(hdr))
    write_if_changed(out / "i18n_catalog.inc", "\n".join(inc))
    write_if_changed(out / "messages.pot", "\n".join(pot))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--sources", type=Path, nargs="+", required=True,
                    help="C++ source files or directories to scan for WA_TR()")
    ap.add_argument("--po", type=Path, nargs="*", default=[])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    try:
        generate(args.sources, args.po, args.out)
    except CatalogError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
