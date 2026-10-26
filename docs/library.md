# `libwifianalyze` – shared library

Directory `libs/wifi-analyze/`, CMake target `wifi_analyze::wifi_analyze`, namespace
`wifi_analyze`.

## Scope

Input: a raw IE byte stream (sequence of `id | length | payload` TLVs) – from
`wpa_cli BSS … ie=`, D-Bus `IEs`, nl80211, or rebuilt from Android
`ScanResult.InformationElement`s – plus optional context.

Output: a fully decoded, loss-free model, a derived per-BSS summary, localized labels,
JSON.

`key=value` input such as `ie=…` is handled by the frontends' input parsers, not by the
library.

Constraints: C++23, standard library only, **no I/O** (callers pass bytes/text), no
exceptions escape the public API, no mutable global state (registries and catalogs are
static read-only tables; a loaded OUI database is an object the caller owns), thread-safe.

## Modules

| Module | Content |
|---|---|
| `core` | bounds-checked byte reader, TLV walker (incl. fragment reassembly), decoder registry |
| `ie` | element decoders (standard / extension / vendor), `DecodedIes`, decoded tree |
| `summary` | `BssSummary` derivation, PHY rate calculation |
| `channel` | frequency ↔ channel/band, operating class tables, channel width geometry |
| `oui` | built-in subset table, `OuiDatabase` parsed from IEEE CSV text |
| `i18n` | message keys, compiled catalogs, locale selection |
| `json` | JSON writer for decoded data and summary |
| `capture` | IE anonymization (`anonymize_ies`), capture format constants/version |

## Public API (draft)

```cpp
namespace wifi_analyze {

struct DecodeContext {
    std::optional<std::uint32_t> frequency_mhz;   // enables band-dependent decoding
    FrameSource source = FrameSource::unknown;     // beacon / probe_response / unknown
    const OuiDatabase* oui = nullptr;              // nullptr → built-in subset only
    DecodeOptions options{};                       // include_raw, max_depth, …
};

// Decoding
DecodedIes  decode(std::span<const std::uint8_t> ies, const DecodeContext& = {});
std::expected<std::vector<std::uint8_t>, Diagnostic> parse_hex(std::string_view); // tolerant: "0x", whitespace, ':' '-'
ElementStream split_elements(std::span<const std::uint8_t> ies);  // raw TLV layer, used by decode()
BssSummary  summarize(const DecodedIes&, const DecodeContext& = {});

// Localization (see i18n.md)
std::span<const std::string_view> available_locales();   // "en", "de", …
Localizer   localizer(std::string_view locale);          // falls back to "en"

// Serialization
std::string to_json(const DecodedIes&, const BssSummary&, const Localizer&, const JsonOptions& = {});

// OUI
std::optional<std::string_view> builtin_oui_name(Oui);
std::expected<OuiDatabase, Error> OuiDatabase::parse_ieee_csv(std::string_view csv_text);

// Channel utilities
std::optional<ChannelInfo>   channel_from_frequency(std::uint32_t mhz);
std::optional<std::uint32_t> frequency_from_channel(std::uint8_t op_class, std::uint8_t chan);

// Capture
std::vector<std::uint8_t> anonymize_ies(std::span<const std::uint8_t>, const AnonymizeOptions&);

// Introspection
std::span<const ElementInfo> supported_elements();

}
```

An optional **C API** (`wifi_analyze_c.h`: `wa_decode_json(bytes, len, ctx, &out)` /
`wa_free`) exists for FFI consumers needing a stable ABI. The JNI bridge uses the C++ API
directly since it is compiled together.

## Data model

### Element identity

```cpp
struct ElementKey {
    std::uint8_t id;                      // 0..255
    std::optional<std::uint8_t> ext_id;   // when id == 255
    std::optional<Oui> oui;               // when id == 221
    std::optional<std::uint8_t> vendor_type;
};
```

Each decoder has a stable string **type key** (`"rsn"`, `"he_operation"`,
`"vendor.microsoft.wmm"`, `"vendor.wfa.mbo_oce"` …) used in JSON and by frontends.

### Decoded element

```cpp
struct DecodedElement {
    ElementKey key;
    std::string_view type_key;
    MessageId name;                       // localized at render/serialize time
    std::size_t offset;                   // of the id byte within the stream
    std::span<const std::uint8_t> raw;    // payload (always kept)
    Status status;                        // ok | truncated | malformed | unknown | partially_decoded
    std::vector<Diagnostic> diagnostics;  // MessageId + arguments
    ElementValue value;                   // std::variant of typed structs (+ Unknown)
    TreeNode tree;
};

struct DecodedIes {
    std::vector<DecodedElement> elements;
    std::vector<Diagnostic> stream_diagnostics;   // trailing bytes, overrun, …
    template<class T> const T* first() const;
    template<class T> std::vector<const T*> all() const;
};
```

### Typed values (layer 1)

Plain structs per element (`Rsn`, `HtCapabilities`, `HeOperation`, `WpsInfo`, …), numbers
and enums only. Used by the summary logic and tests.

### Decoded tree (layer 2)

Generic, nested description – the single thing every UI renders:

```cpp
struct TreeNode {
    std::string_view key;          // stable snake_case: "group_cipher"
    MessageId        label;        // i18n key, e.g. "rsn.group_cipher"
    Value            value;        // none | bool | int | uint | double | string | bytes |
                                   // enum{raw, MessageId} | flags{raw, set MessageIds}
    Unit             unit;         // dBm, MHz, Mbit/s, TU, %, …
    ByteRange        bytes;        // offset+length within the element payload
    std::optional<BitRange> bits;
    Significance     significance; // normal | detail | warning
    std::vector<TreeNode> children;
};
```

Each decoder implements **one** `describe(const T&) -> TreeNode`. Frontends need no
per-element code; they may special-case a `type_key` for richer widgets.

### BSS summary

| Field | Source |
|---|---|
| `ssid`, `hidden` | SSID element |
| `security` label + ciphers, AKMs, PMF, transition modes | RSN, RSNX, WPA vendor IE, OWE transition |
| Wi-Fi generation, PHY standards, band | HT/VHT/HE/EHT presence + frequency |
| primary channel, width, center freq(s), puncturing | DS, HT/VHT/HE/EHT Operation, HE 6 GHz op info |
| max NSS, max PHY rate estimate | HT/VHT/HE/EHT capabilities + width |
| BSS load | BSS Load |
| country, regulatory info | Country, Power Constraint, TPE |
| 802.11k / v / r | RM Enabled Caps, Ext Caps, Mobility Domain |
| WMM, U-APSD, TWT, BSS color | WMM, HE caps/op |
| MLO, multiple BSSID, co-located APs (RNR) | Multi-Link, Multiple BSSID, RNR |
| device hints (manufacturer, model, device/AP name) | WPS, vendor IEs |
| Passpoint / interworking | Interworking, HS2.0 indication, roaming consortium |

## Internal structure

- `core/byte_reader` – cursor with `u8/u16le/u32le/bytes(n)/remaining`, all fallible;
  decoders never touch raw pointers.
- `core/tlv` – walks the stream, reports overrun/trailing bytes, reassembles Fragment
  elements (id 242).
- `core/registry` – static tables mapping `ElementKey` →
  `{type_key, name MessageId, spec_ref, decode_fn, describe_fn}`; separate tables for
  standard, extension and vendor (OUI + type) decoders.
- Sub-element decoding (Multi-Link per-STA profiles, RNR TBTT info, WPS attributes,
  Multiple BSSID profiles) reuses the machinery recursively with a depth limit.

### Adding an element

1. Struct in `include/wifi_analyze/elements/…`.
2. `decode_x(ByteReader&, const DecodeContext&) -> std::expected<X, DecodeError>` and `describe(const X&)`
   in one `.cpp`.
3. One registry line (with spec reference).
4. New message keys in `i18n/messages.pot` (English source text).
5. Unit test with real bytes, golden JSON update, `ie-coverage.md` update.

No changes in CLI or Android needed.

## OUI vendor names

Facts (approximate, to re-check when implementing): the IEEE MA-L registry has ~38 k
entries and grows by roughly 1–2 k per year; `oui.csv` is ~3.5 MB, OUI + organization name
alone ~1.3 MB, ~0.5 MB compressed. Registry changes rarely matter in practice – APs in the
field come from long-established vendors, and randomized/locally administered BSSIDs
never match anyway.

Design (ADR-0006):

- **Built-in subset** (`data/oui-builtin.csv`, a few hundred entries: every OUI we have a
  vendor decoder for + common AP/chipset vendors) compiled into the library. Always available.
- **Full database** optional, supplied at runtime: frontend obtains IEEE `oui.csv`
  (download or import), library parses it via `OuiDatabase::parse_ieee_csv`, caller passes
  it in `DecodeContext`. Lookup order: full DB → built-in subset.
- Frontends cache the file: CLI in `$XDG_CACHE_HOME/wifi-analyze/oui.csv`
  (`~/.cache/…` fallback); Android in the app's `filesDir/oui/`.
- Optionally MA-M / MA-S registries later (28/36-bit prefixes).

## Robustness rules

- Any byte sequence is accepted: shorter-than-minimum → `truncated` with what could be
  read; extra bytes → diagnostic, kept raw.
- Unknown enum values shown as "reserved (n)", never dropped.
- Recursion depth and output size bounded.
- libFuzzer target over `decode` + `summarize` + `to_json` + `parse_ieee_csv`;
  test suite under ASan/UBSan.
