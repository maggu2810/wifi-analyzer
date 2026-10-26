# ADR-0006: OUI vendor names – built-in subset + optional runtime database

Status: proposed · Date: 2026-10-26

## Context
Vendor names for BSSIDs and vendor-specific IEs come from the IEEE OUI registry: ~38 k MA-L
entries (~1.3 MB as prefix + name, ~0.5 MB compressed), growing ~1–2 k/year (approximate).
New registrations rarely matter for WiFi analysis.

## Options
1. Bundle the full table in the library.
2. Download only, on demand.
3. **Small built-in subset + optional full database supplied at runtime.**

## Decision
Option 3. The library compiles in a curated subset (all OUIs with vendor decoders + common
AP/chipset vendors) and can parse IEEE `oui.csv` text into an `OuiDatabase` passed via
`DecodeContext`. Frontends obtain and cache the file:
- CLI: `oui update` (libcurl, optional) / `oui import FILE` → `$XDG_CACHE_HOME/wifi-analyze/oui.csv`.
- Android: "Download vendor database" button and SAF import → app `filesDir/oui/`.

## Consequences
- Library stays small and I/O-free; works offline out of the box.
- Android download needs the `INTERNET` permission, which is install-time and cannot be
  requested lazily; import-only remains possible without it (open question 3).
