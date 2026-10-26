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
| `old/` | Removed once the work is finished – done 2026-10-26 |
| Commits | Agent commits each functional part itself (no push) |
| License | MIT |
| Android SDK levels | minSdk 30 (floor for IE access), compile/targetSdk latest; newer APIs behind `SDK_INT` checks, no feature loss on Android 16/17 |

## Open

None at the moment.
