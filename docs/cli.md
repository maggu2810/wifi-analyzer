# `wifi-analyze-cli`

## Scope

The CLI decodes WiFi data **the user provides**. It does not talk to wpa_supplicant or the
kernel; how the user obtained the IE string is out of scope (Linux scan acquisition is
postponed, see `architecture.md`).

Use cases:
1. Decode an IE hex string, e.g. the `ie=` value of `wpa_cli BSS <id>`.
2. Decode a pasted/piped full `wpa_cli BSS` dump (one or many BSS blocks).
3. Inspect a capture file exported by the Android app (list, sort, show one BSS).
4. Emit JSON for scripting, bug reports and test data.

## Commands (draft)

```
wifi-analyze-cli decode [INPUT]         decode one input; INPUT = hex string, file path, or '-' / omitted = stdin
        [--input-format auto|hex|wpa-bss|capture]
        [--freq MHZ]                    context when input has no frequency (raw hex)
        [--bss BSSID]                   pick one BSS from multi-BSS input
wifi-analyze-cli list [INPUT]           table of all BSSs in a multi-BSS input (wpa-bss-multi / capture)
        [--sort signal|ssid|bssid|channel|band|security|generation] [--reverse]
        [--filter band=5,security=open,ssid~=guest]
wifi-analyze-cli interactive            paste-and-decode loop (like the old prototype)
wifi-analyze-cli elements               list all known/decoded element types
wifi-analyze-cli oui status|update|import FILE|clear
                                        manage the optional full OUI database cache

Global: --format text|json  --lang LANG  --color auto|always|never
        --raw  --hexdump  --verbose (detail-level nodes, diagnostics)  --anonymize
```

Exit codes: `0` ok, `1` usage error, `3` input could not be parsed, `4` OUI download/import failed.

## Inputs

See `data-formats.md` §1. Auto-detection: capture JSON → `wpa_cli BSS` key/value text →
plain hex. For `wpa-bss`, `freq` and `level` are taken over (context + RSSI); `ie=` and
`beacon_ie=` (if present) are decoded and shown separately.

## Output

### `decode` (text)

Summary header, then each element rendered generically from the decoded tree:

```
BSS 00:11:22:33:44:55  "HMR_guest"  2462 MHz (ch 11, 2.4 GHz)  -49 dBm
Security   WPA2-Personal, CCMP-128, PMF capable
PHY        Wi-Fi 6 (802.11ax), 20 MHz, 2 SS, up to 286.8 Mbit/s
Roaming    802.11k ✓  802.11v ✓  802.11r ✗

[48] RSN                                         @42 len 20
  Version ........................ 1
  Group Cipher ................... CCMP-128 (00-0f-ac:4)
  Pairwise Ciphers
    [0] .......................... CCMP-128
  AKM Suites
    [0] .......................... PSK (00-0f-ac:2)
  Capabilities ................... 0x000c
    MFP Required ................. no
    MFP Capable .................. yes
```

Without context (raw hex only), the header shows what is derivable from the IEs alone.
`--hexdump` prints each payload with the byte ranges of fields annotated.

### `list` (text)

```
  SIGNAL     CH   BAND  WIDTH  GEN  SECURITY                SSID          BSSID
  -41 ▇▇▇▇   36   5     80     6    WPA2/WPA3-Personal      HomeNet       aa:bb:cc:00:11:22
  -63 ▇▇▁▁   11   2.4   20     4    WPA2-Personal           HMR_guest     00:11:22:33:44:55
  -80 ▇▁▁▁    6   2.4   20     4    Open                    <hidden>      …
```

Colors by signal quality; insecure configurations (open/WEP/TKIP) highlighted; `NO_COLOR`
respected; terminal width aware.

## OUI cache

- `oui update` downloads the IEEE `oui.csv` (URL configurable, default IEEE standards
  registry) to `$XDG_CACHE_HOME/wifi-analyze/oui.csv`. HTTP via libcurl, optional build
  dependency (`WIFI_CLI_WITH_CURL`); without it only `oui import` is available.
- `oui import FILE` copies a manually downloaded file into the cache.
- If the cache exists it is loaded automatically; otherwise the built-in subset is used.

## Implementation notes

- Rendering is generic over `TreeNode` – no per-element code in the CLI.
- Dependencies: CLI11 (argument parsing), nlohmann/json (reading capture files), optional
  libcurl. Via `FetchContent` (pinned) or system packages.
