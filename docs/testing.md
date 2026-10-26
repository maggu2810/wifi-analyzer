# Testing

## Decoder library (most important)

| Kind | What | Where |
|---|---|---|
| Unit | Each decoder: valid payload, minimum length, truncated, oversized, reserved values | `libs/wifi-analyze/tests/elements/` |
| Golden | Real captures → `to_json` compared with `testdata/golden/*.json` (update script for intentional changes) | `libs/wifi-analyze/tests/golden/` |
| Schema | Golden JSON validated against `docs/schema/decoded.v1.json` | test |
| Property / round-trip | Random TLV streams never crash; every byte is covered by exactly one element; `raw` re-concatenation == input | unit |
| Fuzz | libFuzzer targets (today: `split_elements`, `parse_hex`, `format_message`; later `decode` + `summarize` + `to_json`); seeds in `fuzz/corpus/`, later also from `testdata/captures`; `tools/run_fuzzers.sh [seconds]` | `libs/wifi-analyze/fuzz/` |
| Tools | Python unit tests of the generators (`tools/tests/`), run by ctest | `tools/tests/` |
| Sanitizers | Whole test suite under ASan + UBSan (run locally before finishing library work) | `asan` preset |
| Cross-check | Selected captures compared manually against Wireshark dissection; noted in capture README | `testdata/captures/*/README.md` |

## Test data

`testdata/captures/` holds real-world data, grouped by source:

```
testdata/captures/
  wpa/        wpa_cli BSS dumps, recorded ctrl-socket replies
  dbus/       recorded D-Bus property dumps
  android/    real IE streams / captures from Android (emulator AP so far)
  synthetic/  hand-crafted edge cases (malformed, fragmented, max-length)
```

Every capture gets a short note: device/AP type, band, what's interesting. Only
anonymized or own-network data is committed. The old prototype's sample hex (from
`old/wifi-ie-parser/README.md`) is a good first entry.

## CLI

- CLI: snapshot tests of text and JSON output for `decode` with fixed inputs
  (`--color never`, fixed terminal width).

## Android

- JVM unit tests: `wifi-analyze-native` parses the C++ golden JSON files (`ModelTest`); app:
  sorting/filtering/grouping/history (`NetworkListTest`), capture round trip, CLI capture
  compatibility and IE stream rebuild (`CaptureCodecTest`).
- Instrumented test `NativeDecoderTest`: real JNI library on device/emulator (decode, batch,
  locales, anonymization, OUI database).
- Compose UI tests for list sort/filter and navigation to detail.
- Manual test matrix: at least one device on API 30, one on latest; 2.4/5/6 GHz networks.
