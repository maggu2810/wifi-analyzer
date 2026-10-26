# Roadmap

Implementation starts only after an explicit go from the maintainer.
Scope: library, CLI, Android app. Linux scan acquisition and Qt app are postponed.

## M0 – Skeleton ✅ (2026-10-26)
- Top-level CMake + presets, `.clang-format`, `.clang-tidy`, `.editorconfig`, `.gitignore`.
- `libwifianalyze` skeleton: byte reader, hex parser, TLV walker (fragment reassembly),
  i18n catalog generator + Localizer (English, plus German for the existing messages),
  Catch2 wired, libFuzzer targets + `tools/run_fuzzers.sh`, NDK cross-build preset.
- The decoder **registry moved to M1**: its entry shape depends on the decode/describe
  signatures, which are designed together with the first decoders.
- **Exit:** met – GCC, Clang and ASan/UBSan test runs green, clang-tidy clean, NDK arm64
  build OK, each fuzzer ran 60 s without findings.

## M1 – Library core ✅ (2026-10-26)
- Decoder registry, decoded tree model, `decode()` entry point.
- All **P1** elements (`ie-coverage.md`), decoded tree, `BssSummary`, channel utilities,
  JSON writer + JSON schema v1, built-in OUI subset + IEEE CSV parser.
- Golden tests from first captures (old sample + own APs).
- **Exit:** P1 coverage, ASan/UBSan clean, fuzzer runs 10 min without findings.
- Result: all P1 and most P2 elements decoded (see `ie-coverage.md`), 4 synthetic captures with
  golden JSON, `fuzz_decode` 10 min / 170 k executions without findings. Real captures are still
  to be added (needs data from real APs).

## M2 – CLI ✅ (2026-10-26)
- `decode` (hex, wpa-bss, capture), `list`, `interactive`, `elements`, `oui …`.
- P2 elements as time allows.
- **Exit:** decodes real `wpa_cli BSS` dumps from the maintainer's environment correctly
  (spot-checked against Wireshark). *Open: verification with real dumps by the maintainer.*

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
