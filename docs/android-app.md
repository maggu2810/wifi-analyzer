# Android app

Display name: **Wifi Analyzer**, applicationId `de.maggu2810.android.wifianalyzer`. Distributed by the maintainer (sideload), no Play Store for now.

## Platform baseline

| Item | Choice | Reason |
|---|---|---|
| minSdk | **30** (Android 11) | Floor: `ScanResult.getInformationElements()`, `wifiStandard`, `registerScanResultsCallback` need API 30; below that the core feature (IE decoding) is impossible |
| target/compileSdk | latest stable (Android 17 at implementation time) | all new APIs available to the code |
| Primary test devices | Android 16 and 17 (maintainer's phones) | |
| UI | Kotlin 2.x, Jetpack Compose, Material 3 (dynamic color, dark mode) | |
| Native | NDK + CMake, ABIs `arm64-v8a`, `x86_64` (emulator); `armeabi-v7a` optional | |
| Serialization | kotlinx.serialization (decoder JSON → Kotlin model) | |
| DI | manual (small app); revisit if it grows | fewer moving parts |
| Charts | custom Compose `Canvas` | full control for channel graph; no chart dependency |

### minSdk policy

The lower minSdk costs **no features** on Android 16/17: `minSdk` only defines the oldest
device the APK installs on, while `compileSdk`/`targetSdk` stay at the latest level, so
every new API is available. APIs newer than 30 (e.g. `getWifiSsid()`, `securityTypes`,
MLO getters, `FLAG_INCLUDE_LOCATION_INFO`, newer `WifiManager` capability queries) are
called behind `Build.VERSION.SDK_INT` checks in the `data/` layer; on older devices the
UI hides or marks the corresponding fields as "not available on this Android version".
The price is a few version branches and a test on an API 30 emulator. If such a branch
would ever force a worse behaviour on new devices, the minSdk is raised instead.

## Gradle modules

```
apps/android/
├── settings.gradle.kts
├── gradle/libs.versions.toml
├── wifi-analyze-native/        Android library
│   ├── src/main/cpp/CMakeLists.txt   add_subdirectory(<repo>/libs/wifi-analyze)
│   ├── src/main/cpp/jni_bridge.cpp   thin: bytes in → JSON string out
│   └── src/main/kotlin/…/wifianalyze/  WifiAnalyze API (decode, locale, OUI DB load) + @Serializable model
└── app/
    └── src/main/kotlin/de/maggu2810/android/wifianalyzer/
        ├── data/scan/          WifiManager scan results → Flow<ScanSnapshot>
        ├── data/connection/    ConnectivityManager NetworkCallback → current link info
        ├── data/device/        device WiFi capabilities
        ├── data/export/        capture export (SAF), anonymization toggle
        ├── data/oui/           optional full OUI database: download / import, stored in app files
        ├── domain/             BssObservation (merge + history per BSSID), sorting/filtering
        └── ui/                 screens, components, theme, navigation
```

## Data acquisition – "everything Android exposes"

### Per scan result (`android.net.wifi.ScanResult`)

SSID (`getWifiSsid()` on 33+), BSSID, `level` (RSSI), `frequency`, `channelWidth`,
`centerFreq0/1`, `capabilities` string, `timestamp` (age), `wifiStandard`,
`informationElements` (id, idExt, bytes), `is80211mcResponder`, `isPasspointNetwork`,
`operatorFriendlyName`, `venueName`, `securityTypes` (33+), MLO info
(`apMldMacAddress`, `apMloLinkId`, `affiliatedMloLinks`, newer APIs),
plus any further getters available at the chosen compileSdk – guarded by `SDK_INT`.
Exact availability per API level is checked during implementation and listed in a table here.

Platform-provided values are shown **next to** the values decoded from IEs; mismatches
(e.g. Android's channel width vs. HE/EHT operation) are highlighted – useful for debugging.

### Connected network

Via `ConnectivityManager.NetworkCallback` with `FLAG_INCLUDE_LOCATION_INFO` (31+):
`WifiInfo` (RSSI, tx/rx link speed, max supported speeds, frequency, Wi-Fi standard,
current security type, BSSID/SSID), `LinkProperties` (IPv4/IPv6, gateway, DNS, MTU),
`NetworkCapabilities` (validated, metered, bandwidth estimates).

### Device capabilities

5/6/60 GHz support, supported Wi-Fi standards, WPA3-SAE / Suite-B / OWE support,
scan throttling enabled, max signal level, STA concurrency, etc.

### Optional later: Wi-Fi RTT

`WifiRttManager` ranging to 802.11mc/az responders → distance estimate (P3).

### Scanning constraints (must be visible in the UI)

- `startScan()` throttling: foreground apps ~4 scans / 2 min (configurable off in developer
  options; `isScanThrottleEnabled()` tells). The app shows the remaining budget and also
  consumes results triggered by the system or other apps (`registerScanResultsCallback`).
- Permissions: `ACCESS_FINE_LOCATION` (+ `NEARBY_WIFI_DEVICES` on 33+), location services
  must be enabled. Exact permission matrix to be verified; onboarding screen explains why.

## IE decoding path

1. Rebuild the TLV stream from `informationElements` (`id`, `len`, `[idExt]`, `bytes`) –
   to be verified whether `bytes` already excludes the extension ID; long (>255) payloads
   are re-fragmented / passed as is per what the API delivers.
2. One JNI call per scan batch: `decodeBatch(arrayOf(ies), freqs) : String` (JSON array).
   Runs on `Dispatchers.Default`.
3. Cache decoded results per `(bssid, hash(ies))` – IEs rarely change between scans.
4. kotlinx.serialization maps JSON into `DecodedIes` / `TreeNode` / `BssSummary`.

## Screens

### 1. Network list (home)

- Card per BSS: signal bars + dBm (color by quality), SSID (or *hidden*), BSSID + vendor
  (OUI), band chip, channel + width, Wi-Fi generation badge (4/5/6/6E/7), security icon/label,
  last-seen age; stale entries fade out.
- **Sort**: signal (default), SSID, BSSID, channel, band, security, generation, vendor,
  last seen – ascending/descending; persisted.
- **Filter**: band, security class, generation, hide hidden, free-text search (SSID/BSSID/vendor).
- **Group by SSID** toggle: one row per network, expandable list of its APs/BSSIDs.
- Connected network pinned at top with link info.
- Scan FAB, auto-scan toggle with interval + throttle budget indicator, pull-to-refresh.

### 2. BSS detail (tap on list item)

Sections (tabs or scroll with sticky headers):

- **Overview** – summary (security, PHY, channel, max rate, roaming, load, country, vendor/device hints).
- **Signal** – RSSI timeline for this BSSID during the session, min/avg/max.
- **Security** – ciphers, AKMs, PMF, transition modes, warnings (WEP/TKIP/open).
- **Capabilities** – HT/VHT/HE/EHT as readable grids (MCS/NSS per width, beamforming, TWT…).
- **Channel** – visual of occupied bandwidth, center frequencies, punctured subchannels.
- **Elements** – expandable list of all IEs rendered from the decoded tree; tapping a field
  highlights its bytes in a hex view; diagnostics shown inline.
- **Raw** – full hex; actions: copy (CLI-compatible hex), share, export capture.
- **Platform vs. decoded** – Android-reported values side by side with decoded ones.

### 3. Channel graph

Per band (2.4 / 5 / 6 GHz): each AP drawn as a shape spanning its channel width, height =
RSSI; overlap/congestion visible; tap selects BSS.

### 4. Signal timeline

RSSI over time for selected/top-N BSSIDs.

### 5. Connection & device

Current connection details and device WiFi capabilities.

### 6. Settings

Scan interval, auto-scan, theme, anonymize exports, show detail-level fields, vendor database,
about/licenses.

## State & persistence

- Session history in memory (bounded ring buffer per BSSID).
- Export/import of capture JSON via Storage Access Framework.
- Saved sessions (Room) – later milestone.

## Vendor (OUI) database

The library has a small built-in OUI table (see `library.md`). In **Settings → Vendor
database** the user can optionally:

- **Download** the full IEEE table → stored in `filesDir/oui/` (shows date + entry count,
  "update" button). Needs the `INTERNET` permission. Note: `INTERNET` is an install-time
  ("normal") permission on Android – it cannot be requested only when the button is pressed;
  if declared it is always granted. See open questions (download vs. import-only).
- **Import** an `oui.csv` downloaded elsewhere via the system file picker (SAF) – no
  permission needed.

The file is handed to the library (`load_oui_database(bytes)`), which parses it.

## Localization

- App chrome (menus, buttons, settings, onboarding): Android `res/values*/strings.xml`.
- Decoded data (field labels, enum names, diagnostics): from the library, in the locale
  passed to `decode` (default: the app's current locale, fallback English). See `i18n.md`.
- v1 ships English; German is the first candidate for a second locale.
