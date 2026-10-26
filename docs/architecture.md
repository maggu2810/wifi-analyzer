# Architecture

## Goals

1. Decode as much of the 802.11 IE stream as possible, correctly and safely, **once**,
   in a library shared by every frontend.
2. Linux CLI: take IE data the user provides (hex, `wpa_cli BSS` text, capture file),
   decode it, print it readable or as JSON.
3. Android app: acquire everything Android exposes about nearby and connected networks,
   decode IEs through the same library, present it in a nice, sortable UI.

Postponed: Linux scan acquisition (wpa_supplicant ctrl socket / D-Bus, nl80211) and the
Qt desktop app. The design keeps room for both (see "Future components").

Non-goals: packet capture / monitor mode, active probing with custom frames, iOS, Windows.

## Components

```
              ┌──────────────────────────────────────────────────────┐
              │ libs/wifi-analyze  → libwifianalyze (C++23, no deps)  │
              │  ie/       bytes → typed elements → decoded tree      │
              │  summary/  BSS summary (security, PHY, channel, …)    │
              │  channel/  freq ↔ channel, operating classes          │
              │  oui/      built-in table + loadable full DB          │
              │  i18n/     compiled message catalogs                  │
              │  json/ capture/  JSON writer, IE anonymization        │
              └──────────────▲─────────────────────────▲─────────────┘
                             │                         │ JNI (bytes in, JSON out)
                  ┌──────────┴─────────┐   ┌───────────┴──────────────────┐
                  │ apps/cli           │   │ apps/android                 │
                  │ wifi-analyze-cli   │   │  wifi-analyze-native (bridge)│
                  │ input parsing,     │   │  app: WifiManager, Compose UI│
                  │ text/JSON render   │   └──────────────────────────────┘
                  └────────────────────┘
```

### Is "more than IE decoding" justified in the library?

Yes. IE decoding is the bulk (estimated ~80 % of the shared code), but these parts are
needed identically by every frontend and would otherwise be duplicated:

| Module | Why shared |
|---|---|
| `summary` | Security classification, Wi-Fi generation, width, max rate – the list views of every frontend show it |
| `channel` | Frequency ↔ channel/band/operating class (Annex E tables) – needed for decoding *and* for UI (channel graph) |
| `oui` | Vendor names for BSSIDs and vendor IEs |
| `i18n` | Same wording of decoded data everywhere |
| `capture` | IE anonymization for exports; capture format constants |

Hence the library is named `libwifianalyze` (ADR-0001), with IE decoding as its core module.

### Responsibilities

| Component | Owns | Must not contain |
|---|---|---|
| `libwifianalyze` | everything in the box above | file/network I/O, OS APIs, threads, UI layout |
| `apps/cli` | argument parsing, input format detection, reading files/stdin, capture JSON parsing, terminal rendering, OUI file download/cache | domain logic |
| `apps/android` | Android data acquisition, permissions, history, UI, export/import, OUI file download/import | domain logic (delegated via JNI) |

### Key design decisions (see `decisions/`)

- **ADR-0001** One shared C++23 library `libwifianalyze`.
- **ADR-0002** Typed structs + generic *decoded tree*; frontends render the tree generically.
- **ADR-0003** JNI boundary: bytes in, versioned JSON out.
- **ADR-0004** Monorepo layout below.
- **ADR-0005** i18n of domain text lives in the library.
- **ADR-0006** OUI: small built-in table + optional full database loaded at runtime.

## Directory layout

```
wifi-analyzer/
├── AGENTS.md  README.md  LICENSE
├── CMakeLists.txt              # top level: lib + cli + tests
├── CMakePresets.json
├── .clang-format  .clang-tidy  .editorconfig  .gitignore
├── docs/
│   └── decisions/              # ADRs + open-questions.md
├── libs/
│   └── wifi-analyze/
│       ├── CMakeLists.txt      # standalone-capable; target wifi_analyze::wifi_analyze
│       ├── include/wifi_analyze/
│       │   ├── ie.hpp          # decode entry points, DecodedIes
│       │   ├── elements/…      # typed element structs per area (rsn.hpp, ht.hpp, he.hpp …)
│       │   ├── tree.hpp        # decoded tree model
│       │   ├── summary.hpp     # BssSummary
│       │   ├── channel.hpp
│       │   ├── oui.hpp
│       │   ├── i18n.hpp
│       │   ├── json.hpp
│       │   └── wifi_analyze_c.h  # optional C API
│       ├── src/
│       │   ├── core/           # byte reader, TLV walker, registry
│       │   ├── ie/standard/    # one file per element or family
│       │   ├── ie/ext/         # element-ID-extension decoders (he.cpp, eht.cpp …)
│       │   ├── ie/vendor/      # one file per OUI (microsoft.cpp, wfa.cpp …)
│       │   ├── summary/  channel/  oui/  i18n/  json/  capture/
│       │   └── generated/      # OUI subset table, compiled catalogs (build outputs, not checked in)
│       ├── i18n/               # messages.pot, de.po, …
│       ├── data/               # oui-builtin.csv (curated subset source)
│       ├── tests/
│       └── fuzz/
├── apps/
│   ├── cli/
│   │   ├── CMakeLists.txt
│   │   ├── src/                # main.cpp, commands/, input/, render/, oui_cache/
│   │   └── tests/
│   └── android/                # standalone Gradle project
│       ├── settings.gradle.kts
│       ├── gradle/libs.versions.toml
│       ├── wifi-analyze-native/  # Android library: JNI bridge + Kotlin model
│       └── app/
├── testdata/
│   ├── captures/               # hex / wpa_cli dumps / Android exports (+ README per source)
│   └── golden/                 # expected JSON per capture
└── tools/
    ├── gen_oui_table.py        # curated CSV → generated table
    └── gen_i18n_catalog.py     # .po → generated C++ tables
```

`apps/android` is a standalone Gradle project (rather than Gradle at the repo root): CMake
stays primary; Android Studio opens `apps/android` and compiles the library sources via
CMake `add_subdirectory`. No prebuilt artifacts, no publishing step.

## Data flow

1. **Input** – CLI: user-provided text/file; Android: `ScanResult` incl. raw IEs.
2. **Decode** – `wifi_analyze::decode(ies, context)` → `DecodedIes`.
3. **Summarize** – `wifi_analyze::summarize(decoded, context)` → `BssSummary`.
4. **Localize & serialize** – tree/summary rendered with a chosen locale; JSON for Android
   and `--format json`.
5. **Render** – CLI text tree/table; Android Compose screens.

`context` carries facts not contained in the IE stream (frequency/band, beacon vs. probe
response, locale).

## Cross-platform interoperability

The Android app exports captures in the *capture format* that the CLI accepts as input
(`data-formats.md`): "scan on phone, analyze on desktop", and a steady source of real
test data for `testdata/`.

## Future components (postponed, not to be created now)

- `libs/wifi-scan-linux` – wpa_supplicant ctrl socket + D-Bus, nl80211; would add a
  `scan` command to the CLI and feed the Qt app. Note for later: on NetworkManager desktops
  wpa_supplicant is usually only reachable via D-Bus.
- `apps/qt` – Qt 6 desktop app on top of `libwifianalyze` (+ `wifi-scan-linux`).
