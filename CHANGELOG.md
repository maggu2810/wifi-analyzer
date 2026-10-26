# Changelog

Versions per deliverable (SemVer, see `AGENTS.md` → "Versioning"). Newest first.

## libwifianalyze

### 0.4.0 – 2026-10-26
- RSN overriding (Wi-Fi Alliance WPA3 Specification v3.4): RSN Element Override / Override 2
  and RSNX Override are typed (`RsnOverride`, `RsnxOverride`) and summarized in
  `SecuritySummary::overrides`; `security_label()` shows legacy and overriding configuration;
  JSON `security.display_label` and `security.overrides` (backward compatible).
- Decoders from Wireshark master (a9349d7b): Ubiquiti, Huawei, Meter, Telecom Infra Project and
  Belden AP names, Aruba ARM and AP Health, Wi-Fi Alliance Capabilities element; RSNX octets
  2-5 bits.
- Fix: HE Operation 6 GHz Regulatory Info is 4 bits (was 3) with all defined values.
- `docs/decoder-sources.md` records the Wireshark tag/commit each decoder was checked against.

### 0.3.0 – 2026-10-26
- Vendor decoders for every vendor element Wireshark 4.6.9 understands in beacons: Cisco
  Aironet/CCX (+ element 133), Aruba, Ruckus, Mist, Alcatel-Lucent, Aerohive, Arista, Fortinet,
  Meru, Extreme/Zebra (+ element 173), Extreme mesh, MikroTik, Atheros, Marvell, Nintendo,
  Apple, Broadcom pre-11n HT, French drone remote ID.
- Wi-Fi Alliance: Wi-Fi Display, Wi-Fi Aware (NAN), OSEN, DPP, Multi-AP (EasyMesh), QoS
  Management, RSN Element Override (2) and RSNX Override.
- WPS: more attribute names, WFA vendor extension Multi-AP subelements.
- OUI table: names of the newly decoded vendors.
- Sources of all decoders documented in `docs/decoder-sources.md`.

### 0.2.0 – 2026-10-26
- New decoders: FILS Indication, Target Wake Time, EDCA Parameter Set, Neighbor Report
  (with element-format subelements), QoS Map, Time Advertisement, Time Zone, QoS
  Capability, IBSS DFS, FH / CF Parameter Set, Secondary Channel Offset, BSS Average Access
  Delay, Measurement Pilot Transmission, BSS Available Admission Capacity, 20/40 BSS
  Intolerant Channel Report, BSS Max Idle Period, Extended BSS Load, Wide Bandwidth Channel
  Switch, Channel Switch Wrapper; extension elements UORA, NDP Feedback Report, ESS Report,
  OPS, HE BSS Load, Max Channel Switch Time, TID-to-Link Mapping, Bandwidth Indication.

### 0.1.0 – 2026-10-26
- Baseline: IE decoding (P1 + most P2 elements, see `docs/ie-coverage.md`), BSS summary,
  JSON schema `wifi-analyze.decoded` v1, channel utilities, OUI lookup (built-in subset +
  IEEE CSV), i18n (English, German partially), IE anonymization, capture format v1.
- Country elements without environment octet are decoded (with a warning).

## wifi-analyze-cli

### 0.2.0 – 2026-10-26
- Embeds libwifianalyze 0.4.0; `list` shows the security display label (incl. RSN overriding)
  in a SECURITY column that widens as needed; JSON contains `display_label` / `overrides`.

### 0.1.2 – 2026-10-26
- Embeds libwifianalyze 0.3.0 (vendor elements decoded).

### 0.1.1 – 2026-10-26
- Embeds libwifianalyze 0.2.0 (more elements decoded).

### 0.1.0 – 2026-10-26
- Baseline: `decode`, `list`, `interactive`, `elements`, `oui`; inputs hex, `wpa_cli BSS`
  dumps, capture JSON; text, JSON and capture output; anonymization.

## Android app (de.maggu2810.android.wifianalyzer)

### 0.2.0 (versionCode 4) – 2026-10-26
- Embeds libwifianalyze 0.4.0; network list chips show the security display label (incl. RSN
  overriding), the overview lists the RSN overriding configurations.

### 0.1.2 (versionCode 3) – 2026-10-26
- Embeds libwifianalyze 0.3.0 (vendor elements decoded).

### 0.1.1 (versionCode 2) – 2026-10-26
- Embeds libwifianalyze 0.2.0 (more elements decoded).

### 0.1.0 (versionCode 1) – 2026-10-26
- Baseline: network list (search, filters, sorting, grouping), detail view (overview,
  signal, element trees with hex highlighting, raw), channel graph, signal timeline,
  connection and device information, capture export/import, vendor database, English and
  German UI.
