# Data formats

## 1. Accepted inputs (CLI `decode` and library helpers)

Auto-detected, overridable with `--input-format`:

| Format | Example | Detection |
|---|---|---|
| `hex` | `0009484d525f6775657374…` (spaces, `:`, newlines tolerated) | only hex digits/separators |
| `wpa-bss` | full `wpa_cli BSS <id>` output (`bssid=…`, `freq=…`, `level=…`, `ie=…`, `beacon_ie=…`) | `key=value` lines incl. `ie=` |
| `wpa-bss-multi` | several BSS blocks concatenated (e.g. loop over `wpa_cli bss`) | repeated `bssid=` |
| `capture` | JSON capture produced by this project (Android export; later other tools) | JSON with `"format":"wifi-analyze.capture"` |
| `pcap` | *future* – beacons from a pcap/pcapng | magic bytes |

For `wpa-bss`, `freq` is fed into the `DecodeContext`, `level` is shown as RSSI, and both
`ie` (probe response or beacon IEs) and `beacon_ie` (if present) are decoded and shown
separately.

## 2. Decoded output (JSON)

Produced by `wifi_analyze::to_json`, used by CLI `--format json` and returned over JNI.
Top-level object always carries a schema identifier and version.

```json
{
  "schema": "wifi-analyze.decoded",
  "schema_version": 1,
  "summary": {
    "ssid": "HMR_guest", "hidden": false,
    "security": { "label": "WPA2-Personal", "akms": ["psk"], "pairwise": ["ccmp-128"],
                  "group": "ccmp-128", "pmf": "capable" },
    "phy": { "generation": 6, "standards": ["n","ax"], "band": "2.4",
             "primary_channel": 11, "width_mhz": 20, "center_mhz": [2462],
             "max_nss": 2, "max_phy_rate_mbps": 286.8 },
    "bss_load": { "stations": 3, "utilization_pct": 12.5 },
    "roaming": { "k": true, "v": true, "r": false },
    "country": "DE"
  },
  "elements": [
    {
      "id": 48, "type": "rsn", "name": "RSN", "offset": 42, "length": 20,
      "status": "ok", "raw": "0100000fac040100000fac040100000fac020c00",
      "diagnostics": [],
      "tree": [
        { "key": "version", "label": "Version", "value": 1, "bytes": [0, 2] },
        { "key": "group_cipher", "label": "Group Cipher",
          "value": { "raw": "00-0f-ac:4", "name": "CCMP-128" }, "bytes": [2, 4] }
      ]
    }
  ],
  "diagnostics": []
}
```

Rules:
- `value` is a JSON scalar, or `{raw, name}` for enums, or `{raw, set:[…]}` for flags.
- `bytes` = `[offset, length]` relative to the element payload.
- `significance` omitted when `normal`.
- Field `key`s and `type`s are stable within a schema major version.
- A JSON Schema file (`docs/schema/decoded.v1.json`) is written in M1 and validated
  in tests.

## 3. Capture format (exchange between platforms)

A list of observed BSSs with acquisition metadata and **raw** IE bytes – no decoded data,
so captures stay valid as the decoder improves.

```json
{
  "format": "wifi-analyze.capture",
  "format_version": 1,
  "created": "2026-10-26T12:00:00Z",
  "source": { "platform": "android", "api_level": 35, "device": "Pixel 9", "app_version": "0.1.0" },
  "scans": [
    {
      "timestamp": "2026-10-26T12:00:00Z",
      "bss": [
        {
          "bssid": "00:11:22:33:44:55", "ssid": "MyNetwork",
          "freq_mhz": 5180, "signal_dbm": -49,
          "age_ms": 1200,
          "platform": { "capabilities": "[WPA2-PSK-CCMP][ESS]", "channel_width": 2,
                        "center_freq0": 5210, "wifi_standard": 6 },
          "ies": "0009…",
          "beacon_ies": null
        }
      ]
    }
  ]
}
```

Privacy: exports may be anonymized (`--anonymize` / app toggle): BSSIDs hashed with a
per-export salt, SSIDs replaced, WPS serial/UUID/device names stripped. The IE-level
rewriting (`wifi_analyze::anonymize_ies(bytes)`) lives in the library so both platforms behave
the same; reading/writing the capture JSON itself is done by the frontends (the decoder
library only *writes* JSON and has no JSON parser).
