# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Project status

**Planning phase.** The repository currently contains only planning documents.
Do **not** start implementing code (library, CLI, Android app) until the
maintainer gives an explicit "go". Changes to the docs are welcome when asked.

## What this project is

A WiFi analysis toolset built around one shared library:

| Component | Path | Language | Status |
|---|---|---|---|
| `libwifianalyze` – IE decoding, BSS summary, channel math, OUI, i18n, capture helpers | `libs/wifi-analyze/` | C++23 | planned (M1) |
| `wifi-analyze-cli` – decodes IE data given as input | `apps/cli/` | C++23 | planned (M2) |
| Android app `de.maggu2810.android.wifianalyzer` | `apps/android/` | Kotlin + Compose, JNI to the C++ lib | planned (M3–M4) |
| Linux scan acquisition (`wifi-scan-linux`) | – | – | **postponed, do not create** |
| Qt desktop app | – | – | **postponed, do not create** |

The CLI does **not** acquire scan data. The user supplies the IE string (or `wpa_cli BSS`
text, or a capture file); how they obtained it is out of scope.

Read in this order before working: `docs/architecture.md`, then the document for
the component you touch (see `docs/README.md`).

## Directory layout

```
AGENTS.md  README.md  LICENSE  CMakeLists.txt  CMakePresets.json
docs/                  planning + design docs, ADRs in docs/decisions/
libs/wifi-analyze/     shared library (no platform deps)
apps/cli/              wifi-analyze-cli
apps/android/          Gradle project (compiles libs/wifi-analyze via CMake/NDK)
testdata/              shared real-world captures + golden outputs
tools/                 build-time generators (OUI subset table, i18n catalogs)
old/                   previous prototypes – READ-ONLY inspiration, not built
```

## Hard rules

1. **All WiFi domain logic lives in `libs/wifi-analyze`**: IE decoding, summary
   derivation, channel/frequency math, OUI lookup, domain-text translations, IE
   anonymization. Never re-implement any of it in Kotlin or the CLI. Frontends render
   the library's output.
2. **The decoder handles untrusted input** (bytes from the air). Every read goes through
   the library's bounds-checked byte reader; no raw pointer arithmetic, no UB on
   malformed/truncated data, never crash, never throw out of the public API. Malformed
   data is reported in the result, not hidden.
3. **No data loss.** Unknown or partially decoded elements keep their raw bytes and offsets.
4. The library is platform-independent: C++23 standard library only, no I/O (callers
   pass bytes/text in), no OS headers, no JNI, no third-party runtime deps. It must
   build with the Android NDK and with GCC/Clang on Linux.
5. **No user-visible domain strings hard-coded outside the i18n catalog.** Labels, enum
   names and diagnostics use message keys with English source text (see `docs/i18n.md`).
6. Every decoder cites its spec source (e.g. `IEEE 802.11-2024 §9.4.2.x`, or the vendor
   document) in a comment and has unit tests with real captured bytes where available.
   Cross-check against Wireshark dissectors / Linux `include/linux/ieee80211.h` when in doubt.
7. Do not copy tables or code from `old/` without verifying them: the old reference
   tables contain known errors (see `docs/ie-coverage.md`). Do not modify `old/`.
8. Keep the JSON output schema versioned (`docs/data-formats.md`). A breaking change bumps
   the schema version and updates the golden files under `testdata/`.
9. Every source file starts with an SPDX license header (license: see open questions).
10. Python 3 is a build requirement: generated sources (OUI subset, i18n catalogs) are
    produced at build time into the build tree and are never checked in.

## Coding conventions

### C++
- C++23 (newest standard working on Fedora 45 + current NDK), recent CMake (minimum pinned in M0), Ninja, `CMakePresets.json` (`dev`, `asan`, `fuzz`, `release`).
- Warnings: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow`, `-Werror` in `dev`.
- Formatting via `.clang-format`, static checks via `.clang-tidy` (added in M0).
- Namespaces: `wifi_analyze` (library; sub-namespaces `ie`, `channel`, `oui`, `i18n`,
  `capture` where useful), `wifi_analyze_cli` (CLI).
- Files: `snake_case.hpp/.cpp`; types `PascalCase`; functions/variables `snake_case`.
- Public headers under `include/wifi_analyze/`, private code under `src/`.
- Byte input as `std::span<const std::uint8_t>`; `std::optional` / `std::expected<T, Error>`
  for expected failures instead of exceptions.

### Kotlin / Android
- Kotlin 2.x, Jetpack Compose + Material 3, Gradle Kotlin DSL with a version catalog
  (`gradle/libs.versions.toml`).
- Unidirectional data flow: ViewModel exposes `StateFlow<UiState>`; composables are
  stateless where practical.
- No domain logic in Kotlin; Kotlin maps the library's JSON into model classes
  (kotlinx.serialization) and renders it. UI chrome strings in `strings.xml`.

## Build & test (target state, once implemented)

```bash
cmake --preset dev  && cmake --build --preset dev  && ctest --preset dev
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
cd apps/android && ./gradlew assembleDebug testDebugUnitTest
```

There is no CI for now. Before declaring work done: build, run tests (including the
sanitizer preset for library changes), and update the relevant doc if behaviour changed.

## Working agreements

- Commit each functional part yourself as soon as it builds and its tests pass (small,
  focused commits, meaningful messages). Never push unless asked.
- When a design decision is made or changed, record it as an ADR in `docs/decisions/`.
- Open questions are tracked in `docs/decisions/open-questions.md`; don't silently
  decide them – ask, or use the documented default and say so.
