# Open questions

## Decided (2026-10-26)

| Topic | Decision |
|---|---|
| Scope now | Library, CLI, Android app. `wifi-scan-linux` and Qt app postponed |
| CLI input | User provides IE string / `wpa_cli BSS` text / capture file; acquisition out of scope |
| Library name | `libwifianalyze` in `libs/wifi-analyze` (ADR-0001) |
| CLI binary name | `wifi-analyze-cli` |
| Android applicationId / display name | `de.maggu2810.android.wifianalyzer` / "Wifi Analyzer" |
| Android distribution | Self-distributed (sideload) for now |
| CI | None for now |
| i18n | Domain text in the library (gettext catalogs compiled to tables), app chrome per frontend (ADR-0005) |
| OUI | Small built-in subset + optional full DB via internet download or file import (ADR-0006); Android declares `INTERNET` |
| Test framework | Catch2 v3 |
| C++ / CMake level | Newest that works on the targets: Fedora 45 (GCC/Clang) and current NDK for Android 16 – currently C++23 |
| Generated tables | Generated at build time, not checked in; Python 3 is a build requirement |
| `old/` | Removed once the work is finished |
| Commits | Agent commits each functional part itself (no push) |

## Open

| # | Question | Proposed default |
|---|---|---|
| 1 | License: MIT or Apache-2.0 | MIT (see discussion in chat; decide before M0 so SPDX headers are right) |
| 2 | Android minSdk: 30 (Android 11, first API with IEs) or 36 (Android 16 only, fewer `SDK_INT` branches) | 30 |
