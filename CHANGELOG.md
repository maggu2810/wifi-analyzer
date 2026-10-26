# Changelog

Versions per deliverable (SemVer, see `AGENTS.md` → "Versioning"). Newest first.

## libwifianalyze

### 0.1.0 – 2026-10-26
- Baseline: IE decoding (P1 + most P2 elements, see `docs/ie-coverage.md`), BSS summary,
  JSON schema `wifi-analyze.decoded` v1, channel utilities, OUI lookup (built-in subset +
  IEEE CSV), i18n (English, German partially), IE anonymization, capture format v1.
- Country elements without environment octet are decoded (with a warning).

## wifi-analyze-cli

### 0.1.0 – 2026-10-26
- Baseline: `decode`, `list`, `interactive`, `elements`, `oui`; inputs hex, `wpa_cli BSS`
  dumps, capture JSON; text, JSON and capture output; anonymization.

## Android app (de.maggu2810.android.wifianalyzer)

### 0.1.0 (versionCode 1) – 2026-10-26
- Baseline: network list (search, filters, sorting, grouping), detail view (overview,
  signal, element trees with hex highlighting, raw), channel graph, signal timeline,
  connection and device information, capture export/import, vendor database, English and
  German UI.
