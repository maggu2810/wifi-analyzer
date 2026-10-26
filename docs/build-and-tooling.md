# Build & tooling

## C++ (library + CLI)

- CMake (recent; minimum pinned in M0 to what Fedora 45 and the Android SDK CMake provide), Ninja, `CMakePresets.json`:
  - `dev` – Debug, warnings as errors, tests on
  - `asan` – Debug + AddressSanitizer + UndefinedBehaviorSanitizer
  - `fuzz` – Clang + libFuzzer targets
  - `release` – RelWithDebInfo / Release
- Compilers: GCC and Clang as shipped with Fedora 45; current NDK Clang for Android 16. Language level C++23.
- Top-level options:
  - `WIFI_BUILD_CLI` (ON), `WIFI_BUILD_TESTS` (ON when top level), `WIFI_BUILD_FUZZERS` (OFF)
  - `WIFI_CLI_WITH_CURL` (ON if libcurl found) – enables `oui update`
  - `WIFI_BUILD_QT` (future; not defined yet)
- `libs/wifi-analyze/CMakeLists.txt` must work standalone (`add_subdirectory` from
  Android) and export `wifi_analyze::wifi_analyze` as an alias target; installable with a CMake
  package config for Yocto/system packaging.
- Third-party (apps/tests only): CLI11, nlohmann/json, Catch2 v3 (tests).
  Fetched via `FetchContent` with pinned versions;
  `-DFETCHCONTENT_FULLY_DISCONNECTED=ON` + system packages supported for distro builds.
- `.clang-format`, `.clang-tidy`, `.editorconfig` at repo root.

## Android

- Gradle (Kotlin DSL) wrapper inside `apps/android/`, version catalog.
- AGP, Kotlin, Compose BOM, NDK: latest stable at implementation time, pinned in
  `libs.versions.toml` / `ndkVersion`.
- `wifi-analyze-native` uses `externalNativeBuild { cmake { path = "src/main/cpp/CMakeLists.txt" } }`
  which pulls the decoder sources from `../../libs/wifi-analyze` – no prebuilt binaries.
- ktlint or detekt for Kotlin style (decide in M3).

## CI (not set up for now – planned job list for later)

| Job | Content |
|---|---|
| linux-gcc | dev preset build + ctest |
| linux-clang-asan | asan preset build + ctest |
| fuzz-smoke | run each fuzzer for ~60 s on the corpus |
| format/lint | clang-format check, clang-tidy, Kotlin lint |
| android | `assembleDebug`, unit tests, lint |

## Versioning

SemVer per deliverable (library, CLI, Android app) but released from the monorepo with
tags like `lib-v0.1.0`, `cli-v0.1.0`, `android-v0.1.0`. JSON schema has its own version.

## Generated sources

`tools/gen_oui_table.py` (curated OUI subset) and `tools/gen_i18n_catalog.py` (`.po` →
C++ tables) run as CMake custom commands and write into the build tree (`<build>/generated/`). Generated
files are **not** checked in; Python 3 is a build requirement (also for the Android NDK build).

## License

`LICENSE` at repo root, SPDX header in every source file (license: MIT or Apache-2.0, see open questions).
