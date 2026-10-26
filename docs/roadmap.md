# Roadmap

Implementation starts only after an explicit go from the maintainer.
Scope: library, CLI, Android app. Linux scan acquisition and Qt app are postponed.

## M0 – Skeleton
- Top-level CMake + presets, `.clang-format`, `.clang-tidy`, `.editorconfig`, `.gitignore`.
- `libwifianalyze` skeleton: byte reader, TLV walker, registry, i18n catalog generator
  (English only), test framework wired.
- **Exit:** `cmake --preset dev && ctest` green; TLV walker fuzzed.

## M1 – Library core
- All **P1** elements (`ie-coverage.md`), decoded tree, `BssSummary`, channel utilities,
  JSON writer + JSON schema v1, built-in OUI subset + IEEE CSV parser.
- Golden tests from first captures (old sample + own APs).
- **Exit:** P1 coverage, ASan/UBSan clean, fuzzer runs 10 min without findings.

## M2 – CLI
- `decode` (hex, wpa-bss, capture), `list`, `interactive`, `elements`, `oui …`.
- P2 elements as time allows.
- **Exit:** decodes real `wpa_cli BSS` dumps from the maintainer's environment correctly
  (spot-checked against Wireshark).

## M3 – Android MVP
- Gradle project, `wifi-analyze-native` module with JNI bridge, permissions/onboarding.
- Scan list (sort/filter/group), BSS detail with Overview + Elements + Raw, copy/share hex,
  capture export.
- **Exit:** a capture exported by the app decodes identically in the CLI (golden test on
  emulator + CLI test).

## M4 – Android complete
- Signal history + timeline, channel graph, connection & device screens, capture import,
  anonymization, vendor database download/import, settings, polish.
- German catalog (library) + German `strings.xml`.

## Later
- P3 elements, more vendor decoders, Wi-Fi RTT on Android, pcap input for the CLI.
- `wifi-scan-linux` (wpa_supplicant ctrl/D-Bus, nl80211) + CLI `scan` command.
- Qt desktop app.
- CI.
