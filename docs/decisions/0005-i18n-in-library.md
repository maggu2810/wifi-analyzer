# ADR-0005: Domain-text i18n lives in the library

Status: accepted · Date: 2026-10-26

## Context
Decoded data contains a large, growing set of labels, enum names and diagnostics. They are
produced by the library and shown by every frontend.

## Options
1. Library emits only keys; each frontend translates (Android `strings.xml`, CLI catalog, Qt `.ts`).
2. **Library owns domain-text catalogs**; frontends own only their UI chrome.

## Decision
Option 2. English texts are defined in code (`WA_TR(key, "text")`) and extracted at build time;
translations are gettext `.po` files under `libs/wifi-analyze/i18n/`, compiled into static
tables by `tools/gen_i18n_catalog.py` (no runtime gettext/ICU). Locale is passed on
each decode/serialize call; per-message fallback to English. JSON contains keys **and**
localized labels.

## Consequences
- Adding a decoder adds its keys in one place; all frontends are translated at once.
- Frontends cannot reword domain text individually (acceptable; they can still map keys).
- Translators work with standard `.po` tooling.
