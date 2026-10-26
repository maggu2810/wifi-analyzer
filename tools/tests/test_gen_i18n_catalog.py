# SPDX-License-Identifier: MIT
"""Tests for gen_i18n_catalog.py (run: python3 -m unittest discover -s tools/tests)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gen_i18n_catalog as gen  # noqa: E402

HEADER = 'msgid ""\nmsgstr ""\n"Content-Type: text/plain; charset=UTF-8\\n"\n\n'


def entry(key: str, msgid: str, msgstr: str = "") -> str:
    return f'msgctxt "{key}"\nmsgid "{msgid}"\nmsgstr "{msgstr}"\n\n'


class GeneratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, content: str) -> Path:
        path = self.dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_generates_sorted_enum_and_fallback(self) -> None:
        pot = self.write("messages.pot", HEADER + entry("b.two", "Two {0}") + entry("a.one", "One"))
        po = self.write("de.po", HEADER + entry("b.two", "Two {0}", "Zwei {0}"))
        gen.generate(pot, [po], self.dir / "out")
        hdr = (self.dir / "out/include/wifi_analyze/message_id.hpp").read_text()
        self.assertLess(hdr.index("a_one"), hdr.index("b_two"))
        inc = (self.dir / "out/i18n_catalog.inc").read_text()
        self.assertIn('"Zwei {0}"', inc)
        self.assertIn("catalog_de", inc)

    def test_multiline_and_escapes(self) -> None:
        pot = self.write("messages.pot", HEADER + 'msgctxt "a.b"\nmsgid "x \\"q\\" "\n"y"\nmsgstr ""\n')
        entries = gen.load_source(pot)
        self.assertEqual(entries[0].msgid, 'x "q" y')

    def test_rejects_duplicate_key(self) -> None:
        pot = self.write("messages.pot", HEADER + entry("a.b", "X") + entry("a.b", "Y"))
        with self.assertRaises(gen.CatalogError):
            gen.load_source(pot)

    def test_rejects_invalid_key(self) -> None:
        pot = self.write("messages.pot", HEADER + entry("A.b", "X"))
        with self.assertRaises(gen.CatalogError):
            gen.load_source(pot)

    def test_rejects_colliding_enum_names(self) -> None:
        pot = self.write("messages.pot", HEADER + entry("a.b_c", "X") + entry("a_b.c", "Y"))
        with self.assertRaises(gen.CatalogError):
            gen.generate(pot, [], self.dir / "out")

    def test_rejects_placeholder_mismatch(self) -> None:
        pot = self.write("messages.pot", HEADER + entry("a.b", "X {0}"))
        po = self.write("de.po", HEADER + entry("a.b", "X {0}", "Y {1}"))
        with self.assertRaises(gen.CatalogError):
            gen.generate(pot, [po], self.dir / "out")

    def test_ignores_outdated_translation(self) -> None:
        pot = self.write("messages.pot", HEADER + entry("a.b", "New text"))
        po = self.write("de.po", HEADER + entry("a.b", "Old text", "Alter Text"))
        gen.generate(pot, [po], self.dir / "out")
        inc = (self.dir / "out/i18n_catalog.inc").read_text()
        self.assertNotIn("Alter Text", inc)


if __name__ == "__main__":
    unittest.main()
