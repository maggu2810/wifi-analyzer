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

Produced by `wifi_analyze::to_json` (schema `wifi-analyze.decoded`, version 1), returned over
JNI and embedded in the CLI result. Labels are localized; keys are stable. Examples:
`testdata/golden/*.json`.

```json
{
  "schema": "wifi-analyze.decoded", "schema_version": 1, "locale": "en",
  "summary": {
    "ssid": "HomeNet", "ssid_hex": "486f6d654e6574", "ssid_present": true, "hidden": false,
    "security": { "type": "wpa2_wpa3_personal", "label": "WPA2/WPA3-Personal",
                  "pmf": "capable", "pmf_label": "Capable", "rsn": true, "wpa1": false,
                  "weak": false, "sae_h2e": true, "sae_pk": false,
                  "akms": [{"suite": "00:0f:ac:2", "name": "PSK"}, …],
                  "pairwise_ciphers": […], "group_cipher": {…}, "group_management_cipher": null,
                  "display_label": "WPA2/WPA3-Personal", "overrides": [] },
    "phy": { "generation": 6, "generation_label": "Wi-Fi 6",
             "standards": ["802.11a", "802.11n", "802.11ac", "802.11ax"],
             "band": "5", "band_label": "5 GHz", "primary_channel": 36,
             "primary_frequency_mhz": 5180, "channel_width_mhz": 80, "eighty_plus_eighty": false,
             "center_frequencies_mhz": [5210], "punctured_subchannels": null,
             "max_spatial_streams": 2, "max_rate_mbps": 1201, "max_legacy_rate_mbps": 54 },
    "bss_load": { "station_count": 3, "channel_utilization": 32,
                  "channel_utilization_percent": 12.5, "available_admission_capacity": 0 },
    "country": "DE", "roaming": { "k": true, "v": true, "r": false, "ft_over_ds": false },
    "wmm": true, "uapsd": true, "bss_color": 42, "twt_responder": false,
    "mlo": null, "neighbors": [], "nontransmitted_bssids": 0,
    "device": { "manufacturer": "", "model_name": "", "model_number": "", "device_name": "",
                "serial_number": "" },
    "access_network_type": null, "internet": null, "hotspot20_release": null,
    "vendors": [{"oui": "00:50:f2", "name": "Microsoft"}],
    "element_count": 17, "problem_count": 0
  },
  "overview": [ /* describe(summary) as nodes */ ],
  "elements": [
    { "index": 6, "id": 48, "type": "rsn", "name": "RSN",
      "offset": 42, "stream_length": 26, "length": 24, "content_offset": 0,
      "fragmented": false, "status": "ok", "payload": "0100000fac04…",
      "diagnostics": [],
      "tree": [
        { "key": "common_version", "label": "Version", "text": "1", "value": 1, "bytes": [0, 2] },
        { "key": "rsn_group_cipher", "label": "Group Data Cipher Suite",
          "text": "CCMP-128 (00-0f-ac:4)", "value": 1027076, "value_name": "CCMP-128",
          "bytes": [2, 4] }
      ] }
  ],
  "diagnostics": []
}
```

`security.label` is the legacy type name (RSN element); `security.display_label` is what
frontends show. With RSN overriding (WPA3 Specification v3.4) it reads e.g.
"WPA2-Personal (legacy clients) · WPA3-Personal (RSN overriding)", and `security.overrides`
lists one object per RSN Element Override (`variant` 1) / Override 2 (`variant` 2) with
`type`, `label`, `pmf`, `pmf_label`, `sae_h2e`, `sae_pk`, `akms`, `pairwise_ciphers`,
`group_cipher`, `group_management_cipher` (added in lib 0.4.0; backward compatible, schema
version unchanged).

Node rules: `key` = message key of the label; `text` = display string (`format_value`);
`value` = raw value (bool/number/string; bytes as hex; enums as number plus `value_name`);
optional `unit`, `bytes` = `[offset, length]` relative to the element content (payload from
`content_offset`), `bits` = `[first, count]` LSB-first, `significance` = `detail`|`warning`,
`children`. Element `offset`/`stream_length` are positions in the IE stream; diagnostics'
`bytes` are stream-relative too. Ext. elements additionally carry `ext_id`, vendor elements
`oui` and `vendor_type`.

### CLI result envelope

`wifi-analyze-cli decode|list --format json` wraps one decoded document per BSS:

```json
{ "schema": "wifi-analyze.cli-result", "schema_version": 1,
  "results": [ { "bssid": "aa:bb:cc:00:11:22", "ssid": "HomeNet", "frequency_mhz": 5180,
                 "signal_dbm": -48, "age_ms": 3000,
                 "ies": { /* wifi-analyze.decoded */ }, "beacon_ies": null } ] }
```

`list` emits the same envelope without element trees and payloads.

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
          "age_ms": 1200, "capabilities": 1041,
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

`capabilities` (Capability Information field, optional) lets readers derive the privacy bit.
`platform` is free-form per producer (Android: `capabilities` string etc.; CLI: `flags`).

Privacy: exports may be anonymized (`--anonymize` / app toggle): BSSIDs hashed with a
per-export salt, SSIDs replaced, WPS serial/UUID/device names stripped. The IE-level
rewriting (`wifi_analyze::anonymize_ies(bytes)`) lives in the library so both platforms behave
the same; reading/writing the capture JSON itself is done by the frontends (the decoder
library only *writes* JSON and has no JSON parser).
