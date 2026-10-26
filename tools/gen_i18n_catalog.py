#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile gettext message catalogs into C++ tables for libwifianalyze.

Source of truth is a .pot file in which every entry has
  msgctxt "<key>"      stable message key, e.g. "tlv.truncated"
  msgid   "<English>"  English source text, may contain positional placeholders {0}, {1}, ...
Translations are <locale>.po files with the same msgctxt/msgid and a msgstr.
An empty msgstr means "not translated" (falls back to English at runtime).

Outputs:
  <out>/include/wifi_analyze/message_id.hpp   enum class MessageId
  <out>/i18n_catalog.inc                      constexpr tables (included by src/i18n/)
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")
LOCALE_RE = re.compile(r"^[a-z]{2,3}(_[A-Z]{2})?$")
PLACEHOLDER_RE = re.compile(r"(?<!\{)\{(\d+)\}(?!\})")


class CatalogError(Exception):
    pass


@dataclass
class Entry:
    key: str
    msgid: str
    msgstr: str
    line: int
    comments: list[str] = field(default_factory=list)


def unescape(s: str, where: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 1
            if i >= len(s):
                raise CatalogError(f"{where}: dangling backslash")
            esc = s[i]
            mapping = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
            if esc not in mapping:
                raise CatalogError(f"{where}: unsupported escape \\{esc}")
            out.append(mapping[esc])
        else:
            out.append(c)
        i += 1
    return "".join(out)


def parse_po(path: Path) -> list[Entry]:
    """Minimal .po/.pot parser: msgctxt/msgid/msgstr with continuation lines."""
    entries: list[Entry] = []
    current: dict[str, str] = {}
    comments: list[str] = []
    field_name: str | None = None
    start_line = 0

    def flush() -> None:
        nonlocal current, comments, field_name
        if current:
            if "msgid" not in current or "msgstr" not in current:
                raise CatalogError(f"{path}:{start_line}: incomplete entry")
            key = current.get("msgctxt")
            if key is None:
                # The header entry (msgid "") has no context; everything else needs one.
                if current["msgid"] != "":
                    raise CatalogError(f"{path}:{start_line}: entry without msgctxt key")
            else:
                entries.append(Entry(key, current["msgid"], current["msgstr"], start_line, comments))
        current = {}
        comments = []
        field_name = None

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith("#"):
            if current:
                flush()
            if line.startswith("#."):
                comments.append(line[2:].strip())
            continue
        m = re.match(r'^(msgctxt|msgid|msgstr)\s+"(.*)"$', line)
        if m:
            name, value = m.group(1), m.group(2)
            if name == "msgctxt" or (name == "msgid" and "msgctxt" not in current):
                if current and name in current:
                    flush()
            if not current:
                start_line = lineno
            if name in current:
                raise CatalogError(f"{path}:{lineno}: duplicate {name}")
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


def enum_name(key: str) -> str:
    return key.replace(".", "_")


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


def load_source(pot: Path) -> list[Entry]:
    entries = parse_po(pot)
    seen: dict[str, Entry] = {}
    for e in entries:
        if not KEY_RE.match(e.key):
            raise CatalogError(f"{pot}:{e.line}: invalid key {e.key!r}")
        if e.key in seen:
            raise CatalogError(f"{pot}:{e.line}: duplicate key {e.key!r}")
        if not e.msgid:
            raise CatalogError(f"{pot}:{e.line}: empty English text for {e.key!r}")
        seen[e.key] = e
    return sorted(entries, key=lambda e: e.key)


def load_translation(po: Path, source: dict[str, Entry]) -> dict[str, str]:
    result: dict[str, str] = {}
    for e in parse_po(po):
        src = source.get(e.key)
        if src is None:
            print(f"warning: {po}:{e.line}: key {e.key!r} not in source catalog (ignored)",
                  file=sys.stderr)
            continue
        if not e.msgstr:
            continue
        if e.msgid != src.msgid:
            print(f"warning: {po}:{e.line}: {e.key!r} translates an outdated English text "
                  "(ignored, falls back to English)", file=sys.stderr)
            continue
        if placeholders(e.msgstr) != placeholders(src.msgid):
            raise CatalogError(f"{po}:{e.line}: placeholders of {e.key!r} differ from the source")
        result[e.key] = e.msgstr
    return result


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8")


def generate(pot: Path, pos: list[Path], out: Path) -> None:
    entries = load_source(pot)
    source = {e.key: e for e in entries}

    names = [enum_name(e.key) for e in entries]
    if len(set(names)) != len(names):
        raise CatalogError("message keys collide after conversion to enum names")

    locales: list[tuple[str, dict[str, str]]] = [("en", {e.key: e.msgid for e in entries})]
    for po in sorted(pos):
        locale = po.stem
        if not LOCALE_RE.match(locale) or locale == "en":
            raise CatalogError(f"{po}: file name must be a locale like 'de' or 'pt_BR'")
        locales.append((locale, load_translation(po, source)))

    hdr = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by tools/gen_i18n_catalog.py from i18n/messages.pot – do not edit.",
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
    for e, name in zip(entries, names):
        hdr.append(f"    {name}, ///< {e.key}: {e.msgid.splitlines()[0]}")
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
        f"inline constexpr std::array<std::string_view, {n}> message_keys{{",
    ]
    inc += [f"    {cxx_string(e.key)}," for e in entries]
    inc.append("};")
    inc.append("")
    for locale, texts in locales:
        inc.append(f"inline constexpr std::array<std::string_view, {n}> catalog_{locale}{{")
        for e in entries:
            text = texts.get(e.key)
            inc.append(f"    {cxx_string(text)}," if text else "    {},")
        inc.append("};")
        inc.append("")
    inc.append(f"inline constexpr std::array<LocaleCatalog, {len(locales)}> catalogs{{{{")
    for locale, _ in locales:
        inc.append(f"    {{{cxx_string(locale)}, &catalog_{locale}}},")
    inc.append("}};")
    inc.append("")

    write_if_changed(out / "include" / "wifi_analyze" / "message_id.hpp", "\n".join(hdr))
    write_if_changed(out / "i18n_catalog.inc", "\n".join(inc))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--pot", type=Path, required=True)
    ap.add_argument("--po", type=Path, nargs="*", default=[])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    try:
        generate(args.pot, args.po, args.out)
    except CatalogError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
