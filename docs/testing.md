# Testing

## Decoder library (most important)

| Kind | What | Where |
|---|---|---|
| Unit | Each decoder: valid payload, minimum length, truncated, oversized, reserved values | `libs/wifi-analyze/tests/elements/` |
| Golden | Real captures → `to_json` compared with `testdata/golden/*.json` (update script for intentional changes) | `libs/wifi-analyze/tests/golden/` |
| Schema | Golden JSON validated against `docs/schema/decoded.v1.json` | test |
| Property / round-trip | Random TLV streams never crash; every byte is covered by exactly one element; `raw` re-concatenation == input | unit |
| Fuzz | libFuzzer on `decode` + `summarize` + `to_json`; corpus seeded from `testdata/captures` | `libs/wifi-analyze/fuzz/` |
| Sanitizers | Whole test suite under ASan + UBSan (run locally before finishing library work) | `asan` preset |
| Cross-check | Selected captures compared manually against Wireshark dissection; noted in capture README | `testdata/captures/*/README.md` |

## Test data

`testdata/captures/` holds real-world data, grouped by source:

```
testdata/captures/
  wpa/        wpa_cli BSS dumps, recorded ctrl-socket replies
  dbus/       recorded D-Bus property dumps
  android/    capture JSON exported from the app (anonymized)
  synthetic/  hand-crafted edge cases (malformed, fragmented, max-length)
```

Every capture gets a short note: device/AP type, band, what's interesting. Only
anonymized or own-network data is committed. The old prototype's sample hex (from
`old/wifi-ie-parser/README.md`) is a good first entry.

## CLI

- CLI: snapshot tests of text and JSON output for `decode` with fixed inputs
  (`--color never`, fixed terminal width).

## Android

- JVM unit tests: JSON → model mapping, sorting/filtering/grouping, history merging.
- Instrumented test: JNI bridge loads and decodes a known capture on emulator (x86_64).
- Compose UI tests for list sort/filter and navigation to detail.
- Manual test matrix: at least one device on API 30, one on latest; 2.4/5/6 GHz networks.
