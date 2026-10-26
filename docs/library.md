# `libwifianalyze` – shared library

Directory `libs/wifi-analyze/`, CMake target `wifi_analyze::wifi_analyze`, namespace
`wifi_analyze`. Status: M1 implemented.

## Scope

Input: a raw IE byte stream (sequence of `id | length | payload` TLVs) – from
`wpa_cli BSS … ie=`, D-Bus `IEs`, nl80211, or rebuilt from Android
`ScanResult.InformationElement`s – plus optional context.

Output: a fully decoded, loss-free model, a derived per-BSS summary, localized labels,
JSON. `key=value` input such as `ie=…` is handled by the frontends' input parsers.

Constraints: C++23, standard library only, **no I/O**, no exceptions escape the public API,
no mutable global state (registries and catalogs are static read-only tables; a loaded OUI
database is an object owned by the caller), thread-safe.

## Public headers

| Header | Content |
|---|---|
| `ie.hpp` | `DecodeContext`, `ElementKey`, `DecodedElement`, `DecodedIes`, `decode()`, `known_elements()` |
| `elements.hpp` | typed values (`Rsn`, `HtCapabilities`, `HeOperation`, `Wps`, …) and `ElementValue` |
| `tree.hpp` | `TreeNode`, `Value`, `EnumValue`, `Text`, `Unit`, `Display`, `Significance`, `format_value()` |
| `summary.hpp` | `BssSummary` (+ security/PHY/…), `summarize()`, `describe()`, naming helpers, `phy_rate_mbps()` |
| `json.hpp` | `to_json()` (schema `wifi-analyze.decoded` v1) |
| `i18n.hpp` | `Localizer`, `localizer()`, `available_locales()`, `message_key()`, `format_message()` |
| `channel.hpp` | `Band`, frequency ↔ channel, operating class → band |
| `oui.hpp` | `OuiDatabase::parse_ieee_csv()`, `builtin_oui_name()`, `oui_name()`, `oui_of_mac()` |
| `capture.hpp` | capture format id/version, `anonymize_ies()`, `anonymize_mac()`, `anonymize_ssid()` |
| `tlv.hpp`, `hex.hpp` | raw TLV layer `split_elements()`, `parse_hex()` / `to_hex()` |
| `message_id.hpp` | generated `enum class MessageId` (build tree) |

Typical use:

```cpp
wifi_analyze::DecodeContext ctx{.frequency_mhz = 5180};
const auto ies = wifi_analyze::decode(bytes, ctx);
const auto summary = wifi_analyze::summarize(ies, ctx);
const auto json = wifi_analyze::to_json(ies, summary, wifi_analyze::localizer("de"));
```

## Data model

### Decoded element

`DecodedElement` = `RawElement` (id, ext id, stream range, payload, fragments) + `ElementKey`
(id / ext id / OUI / vendor type) + stable `type` key (`"rsn"`, `"he_operation"`,
`"vendor.microsoft.wmm"`, `"unknown"`) + `name` (MessageId) + `DecodeStatus`
(`ok | unknown | malformed | truncated`) + diagnostics + typed `value` + `tree`.

### Typed values (layer 1)

Plain structs for the elements that the summary or frontends use programmatically; other
elements have only a tree (`std::monostate` value).

### Decoded tree (layer 2)

```cpp
struct TreeNode {
    MessageId label;                 // message_key(label) = stable machine key
    Value value;                     // none | bool | int | uint | double | string | bytes | EnumValue
    Unit unit;                       // dBm, MHz, Mbit/s, TU, µs, %, octets, …
    Display display;                 // decimal | hex | suite ("00-0f-ac:4") | name_only
    std::optional<ByteRange> bytes;  // relative to the element content
    std::optional<BitRange> bits;    // LSB-first ("B0") within `bytes`
    Significance significance;       // normal | detail | warning
    std::vector<TreeNode> children;
};
```

- `format_value(node, localizer)` produces the display text ("CCMP-128 (00-0f-ac:4)",
  "-49 dBm", "yes", "0x000c") so every frontend shows identical strings.
- Nodes labelled `common_item` are list entries (render as bullets).
- `Text` is either a `MessageId` (translated) or a technical literal (never translated).
- Byte ranges are relative to `DecodedElement::content()` (the payload without the extension
  ID octet). Nested elements (Multiple BSSID profiles) are shifted into the outer content.
  Diagnostics carry **stream**-relative ranges.

### BSS summary

`summarize()` derives: SSID/hidden; security type (open, WEP, OWE, WPA/WPA2/WPA3 personal
and enterprise variants incl. transition modes, Suite-B 192), PMF, ciphers, AKMs, SAE-H2E/PK,
`weak` flag; Wi-Fi generation, standards, band, primary channel/frequency, operating width
(HT → VHT → HE 6 GHz → EHT, 80+80, ext. NSS BW via HT CCFS2), center frequencies, EHT
puncturing, max NSS, estimated max PHY rate (`N_SD × bits × R / T_sym`); BSS load, country,
802.11k/v/r, WMM/U-APSD, BSS color, TWT, MLO, RNR neighbors, nontransmitted BSSIDs, WPS
device info, Interworking/Hotspot 2.0, vendor OUIs, problem count.

`describe(summary)` renders the summary as a tree (the "overview" every frontend shows).

## Internal structure

```
src/core/    byte_reader.hpp (bounds-checked), tlv.cpp (split + fragment reassembly),
             decoder.hpp/.cpp (Decoder helper, BitField, decode driver, nested decoding),
             registry.hpp, tr.hpp (WA_TR macro + common messages)
src/ie/      registry.cpp (tables), one file per element family / vendor
src/summary/ summary + PHY rate model
src/json/    JSON writer      src/tree/  format_value      src/oui/  OUI lookup + CSV parser
src/channel/ channel math     src/capture/ anonymization    src/i18n/  catalog lookup
```

A decoder is **one function** `ElementValue decode_x(Decoder& d)`: it reads fields through
the `Decoder` helpers (`u8/u16/…`, `bits()` + `BitField::flag/number/enumeration`,
`enumeration()`, `mac()`, `oui()`, `text()`, `rest()`, `nested_elements()`, `sub_decode()` for
subelements in element format), which append tree
nodes with exact byte/bit ranges, and fills the typed value where one exists. Too-short content
marks the element malformed and keeps the partial result; unread octets after the decoder
become an "Unparsed Data" node plus a warning.

### Adding an element

1. Write `decode_x()` in the fitting `src/ie/*.cpp` (labels via `WA_TR(key, "Text")`).
2. Declare it in `src/ie/decoders.hpp`, add one line to the table in `src/ie/registry.cpp`.
3. If the summary needs it: typed struct in `elements.hpp` + `ElementValue`.
4. Tests (real bytes where possible), regenerate golden files if output changed
   (`WIFI_UPDATE_GOLDEN=1 ctest -R golden`), update `ie-coverage.md` and add the source row to
   `decoder-sources.md` (standard / vendor spec + cross-checked Wireshark dissector).

No changes in the CLI or Android are needed.

## OUI vendor names

Facts (approximate): the IEEE MA-L registry has ~38 k entries and grows by roughly 1–2 k per
year; `oui.csv` is ~3.5 MB. Registry changes rarely matter in practice; randomized/locally
administered BSSIDs never match anyway (`oui_of_mac()` returns nullopt for them).

- **Built-in subset**: `data/oui-builtin.csv` (OUIs with vendor decoders + common AP/chipset
  vendors), compiled into a table at build time by `tools/gen_oui_table.py`.
- **Full database** (optional): the frontend obtains IEEE `oui.csv` (download or import), the
  library parses it (`OuiDatabase::parse_ieee_csv`), the caller passes it in
  `DecodeContext::oui_database`. Lookup: full database → built-in subset.
- Caches: CLI `$XDG_CACHE_HOME/wifi-analyze/oui.csv`; Android app files dir.

## Robustness

- Any byte sequence is accepted; problems are reported, never thrown.
- Unknown enum values are shown as "Reserved"; unknown capability bits as numbered entries.
- Nesting depth is bounded (`DecodeContext::max_depth`, default 4).
- Fuzz targets: `decode` (full pipeline incl. JSON), `split_elements`, `parse_hex`,
  `format_message`; the test suite runs under ASan/UBSan.
