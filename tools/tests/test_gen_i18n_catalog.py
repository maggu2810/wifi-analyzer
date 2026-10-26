# SPDX-License-Identifier: MIT
"""Tests for gen_i18n_catalog.py (run: python3 -m unittest discover -s tools/tests)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gen_i18n_catalog as gen  # noqa: E402

PO_HEADER = 'msgid ""\nmsgstr ""\n"Content-Type: text/plain; charset=UTF-8\\n"\n\n'


def po_entry(key: str, msgid: str, msgstr: str = "") -> str:
    return f'msgctxt "{key}"\nmsgid "{msgid}"\nmsgstr "{msgstr}"\n\n'


class GeneratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / "src").mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def source(self, content: str, name: str = "a.cpp") -> Path:
        path = self.dir / "src" / name
        path.write_text(content, encoding="utf-8")
        return path

    def write(self, name: str, content: str) -> Path:
        path = self.dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_extracts_sorted_and_deduplicated(self) -> None:
        self.source('x(WA_TR(b_two, "Two {0}")); y(WA_TR(a_one, "One")); WA_TR(b_two, "Two {0}");')
        entries = gen.extract_sources([self.dir / "src"])
        self.assertEqual([e.key for e in entries], ["a_one", "b_two"])

    def test_concatenated_literals_and_escapes(self) -> None:
        self.source('WA_TR(a_b,\n   "x \\"q\\" "\n   "y")')
        self.assertEqual(gen.extract_sources([self.dir / "src"])[0].msgid, 'x "q" y')

    def test_macro_definition_is_not_a_message(self) -> None:
        self.source('#define WA_TR(id, text) (id)\nWA_TR(a_b, "X")')
        self.assertEqual(len(gen.extract_sources([self.dir / "src"])), 1)

    def test_rejects_conflicting_text(self) -> None:
        self.source('WA_TR(a_b, "X")')
        self.source('WA_TR(a_b, "Y")', "b.cpp")
        with self.assertRaises(gen.CatalogError):
            gen.extract_sources([self.dir / "src"])

    def test_rejects_invalid_key(self) -> None:
        self.source('WA_TR(Bad_Key, "X")')
        with self.assertRaises(gen.CatalogError):
            gen.extract_sources([self.dir / "src"])

    def test_generates_outputs_with_translation(self) -> None:
        self.source('WA_TR(a_b, "Two {0}")')
        po = self.write("de.po", PO_HEADER + po_entry("a_b", "Two {0}", "Zwei {0}"))
        gen.generate([self.dir / "src"], [po], self.dir / "out")
        self.assertIn("a_b,", (self.dir / "out/include/wifi_analyze/message_id.hpp").read_text())
        self.assertIn('"Zwei {0}"', (self.dir / "out/i18n_catalog.inc").read_text())
        self.assertIn('msgctxt "a_b"', (self.dir / "out/messages.pot").read_text())

    def test_rejects_placeholder_mismatch(self) -> None:
        self.source('WA_TR(a_b, "X {0}")')
        po = self.write("de.po", PO_HEADER + po_entry("a_b", "X {0}", "Y {1}"))
        with self.assertRaises(gen.CatalogError):
            gen.generate([self.dir / "src"], [po], self.dir / "out")

    def test_ignores_outdated_translation(self) -> None:
        self.source('WA_TR(a_b, "New text")')
        po = self.write("de.po", PO_HEADER + po_entry("a_b", "Old text", "Alter Text"))
        gen.generate([self.dir / "src"], [po], self.dir / "out")
        self.assertNotIn("Alter Text", (self.dir / "out/i18n_catalog.inc").read_text())


if __name__ == "__main__":
    unittest.main()
