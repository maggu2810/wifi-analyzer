# IE coverage plan

Priority tiers:

- **P1** – milestone M1, required for a useful summary (security, PHY, channel).
- **P2** – M1/M2 stretch, commonly seen in beacons and interesting to show.
- **P3** – later; rare or very complex. Until decoded they appear as raw + named.

**Status (lib 0.3.0):** every standard / extension element that can appear in a beacon or
probe response is decoded; `wifi-analyze-cli elements` prints the authoritative list (decoded
vs. named-only). Named-only on purpose: elements that only occur in other frames (TSPEC,
TCLAS, measurement request/report, FTE, timeout interval, power capability, supported
channels, SSID list, known BSSID, UL MU power, password identifier, …), element 68 (ID
conflict BSS AC Access Delay / WAPI) and DMG/S1G elements. The source of every decoder is
listed in `docs/decoder-sources.md`. Vendor elements are decoded where a Wi-Fi Alliance
specification or a Wireshark 4.6.9 dissector exists.

Every element that is not decoded is still **named** (from the full Element ID table)
and kept raw. The "Spec" column is filled in during implementation with the exact
clause of IEEE 802.11-2024 (or the amendment / vendor spec).

> ⚠️ The tables of the earlier prototype (removed) contained errors (e.g. HE 6 GHz Band
> Capabilities is Ext ID **59**, not 106; Ext 106/107/108 are EHT Operation / Multi-Link /
> EHT Capabilities; Element 240 is **FILS Indication**, not proprietary). All IDs below are
> verified against the standard / Linux `ieee80211.h` / Wireshark.

## Standard elements

| ID | Name | Tier | Notes |
|---|---|---|---|
| 0 | SSID | P1 | Detect hidden (len 0 or zero-filled); non-UTF-8 shown escaped |
| 1 | Supported Rates | P1 | Basic-rate flag, BSS membership selectors (HT/VHT/HE/SAE-H2E) |
| 2 | FH Parameter Set | P3 | Obsolete FH PHY |
| 3 | DSSS Parameter Set | P1 | Current channel |
| 4 | CF Parameter Set | P3 | |
| 5 | TIM | P2 | DTIM count/period, bitmap |
| 7 | Country | P1 | Country code, environment, triplets / operating-class triplets |
| 11 | BSS Load | P1 | Stations, utilization %, admission capacity |
| 12 | EDCA Parameter Set | P2 | QoS info + 4 AC records (as WMM) |
| 32 | Power Constraint | P2 | |
| 35 | TPC Report | P2 | |
| 37 | Channel Switch Announcement | P2 | |
| 40 | Quiet | P3 | |
| 41 | IBSS DFS | P3 | Channel map entries |
| 42 | ERP Information | P2 | |
| 45 | HT Capabilities | P1 | Full cap info, A-MPDU params, MCS set, ext caps, TxBF, ASEL |
| 46 | QoS Capability | P3 | AP form |
| 48 | RSN | P1 | Ciphers, AKMs (full suite table), capabilities, PMKID, group mgmt cipher |
| 50 | Extended Supported Rates | P1 | Merged with ID 1 in summary |
| 51 | AP Channel Report | P2 | |
| 52 | Neighbor Report | P3 | BSSID info, subelements (element-format ones decoded) |
| 54 | Mobility Domain | P1 | 802.11r detection |
| 59 | Supported Operating Classes | P2 | |
| 61 | HT Operation | P1 | Primary channel, secondary offset, protection |
| 69 | Time Advertisement | P3 | Incl. UTC time value |
| 62 / 63 | Secondary Channel Offset / BSS Average Access Delay | P3 | |
| 66 / 67 | Measurement Pilot / BSS Available Admission Capacity | P3 | |
| 70 | RM Enabled Capabilities | P1 | 802.11k bits |
| 71 | Multiple BSSID | P2 | Non-transmitted BSSID profiles (recursive) |
| 72 | 20/40 BSS Coexistence | P2 | |
| 73 | 20/40 BSS Intolerant Channel Report | P3 | |
| 74 | Overlapping BSS Scan Params | P3 | |
| 90 | BSS Max Idle Period | P3 | |
| 98 | Time Zone | P3 | POSIX TZ string |
| 107 | Interworking | P2 | Access network type, internet, ASRA, HESSID |
| 108 | Advertisement Protocol | P2 | ANQP |
| 110 | QoS Map | P3 | DSCP exceptions + ranges |
| 111 | Roaming Consortium | P2 | |
| 113 / 114 | Mesh Configuration / Mesh ID | P3 | |
| 127 | Extended Capabilities | P1 | Full bit table (BSS transition/11v, interworking, TWT, FTM, …) |
| 191 | VHT Capabilities | P1 | Incl. MCS/NSS maps |
| 192 | VHT Operation | P1 | Channel width, center segments |
| 193 / 194 | Extended BSS Load / Wide Bandwidth Channel Switch | P3 | |
| 195 | Transmit Power Envelope | P2 | |
| 196 | Channel Switch Wrapper | P3 | Nested elements |
| 199 | Operating Mode Notification | P2 | |
| 201 | Reduced Neighbor Report | P2 | TBTT info → co-located (6 GHz) APs |
| 216 | Target Wake Time | P2 | Individual and broadcast parameter sets |
| 240 | FILS Indication | P2 | FILS info bits, cache id, HESSID, realms, public keys |
| 242 | Fragment | P1 | Handled by TLV reassembly |
| 244 | RSN Extension (RSNXE) | P1 | SAE-H2E, SAE-PK |
| 221 | Vendor Specific | – | See vendor table |
| 255 | Element ID Extension | – | See extension table |

## Extension elements (ID 255)

| Ext ID | Name | Tier |
|---|---|---|
| 35 | HE Capabilities | P1 (MAC + PHY caps, MCS/NSS maps per width, PPE thresholds raw) |
| 36 | HE Operation | P1 (BSS color, VHT op info, 6 GHz operation info) |
| 37 | UORA Parameter Set | P3 |
| 38 | MU EDCA Parameter Set | P2 |
| 39 | Spatial Reuse Parameter Set | P2 |
| 41 | NDP Feedback Report Parameter Set | P3 |
| 42 | BSS Color Change Announcement | P3 |
| 45 / 46 / 47 | ESS Report / OPS / HE BSS Load | P3 |
| 52 | Max Channel Switch Time | P3 |
| 55 | Multiple BSSID Configuration | P2 |
| 56 | Non-Inheritance | P3 |
| 58 | Short SSID List | P3 |
| 59 | HE 6 GHz Band Capabilities | P1 |
| 106 | EHT Operation | P1 (width incl. 320 MHz, disabled subchannel bitmap / puncturing) |
| 107 | Multi-Link | P2 (basic variant first, per-STA profiles) |
| 108 | EHT Capabilities | P1 |
| 109 | TID-To-Link Mapping | P3 |
| 135 | Bandwidth Indication | P3 |

## Vendor-specific elements (ID 221)

| OUI | Type | Name | Tier |
|---|---|---|---|
| 00:50:F2 (Microsoft) | 1 | WPA (legacy) | P1 |
| 00:50:F2 | 2 | WMM Information / Parameter | P1 |
| 00:50:F2 | 4 | WPS (attribute TLVs: state, device name, manufacturer, model, serial, UUID, config methods, …) | P1 |
| 50:6F:9A (Wi-Fi Alliance) | 0x09 | P2P | P2 |
| 50:6F:9A | 0x10 | Hotspot 2.0 Indication | P2 |
| 50:6F:9A | 0x16 | MBO-OCE | P2 |
| 50:6F:9A | 0x1C | OWE Transition Mode | P1 |
| 50:6F:9A | 0x0A / 0x13 / 0x14 | Wi-Fi Display / Wi-Fi Aware (NAN) / OSEN | P3 |
| 50:6F:9A | 0x1A / 0x1B / 0x22 | DPP (raw) / Multi-AP (EasyMesh) / QoS Management | P3 |
| 50:6F:9A | 0x29 / 0x2A / 0x2B | RSN Element Override (2) / RSNX Override (WPA3 v3.4) | P2 |
| 00:40:96 (Cisco) | various | Aironet / CCX: DTPC, CCX version, QoS, QBSS v2, client MFP, AP name v2 (+ element 133 CCX1 device name) | P3 |
| 00:0B:86 (Aruba), 00:13:92 (Ruckus), 5C:5B:35 (Mist), DC:08:56 (Alcatel-Lucent), 00:19:77 (Aerohive), 00:11:74 (Arista), 00:09:0F (Fortinet), 00:A0:F8 (Extreme/Zebra, + element 173), 00:0C:42 (MikroTik) | – | AP name / identity and further Wireshark-known fields | P3 |
| 00:0C:E6 (Meru), 00:05:12 (Extreme mesh), 00:03:7F (Atheros), 00:50:43 (Marvell), 00:1F:32 (Nintendo), 00:17:F2 (Apple), 00:90:4C (Broadcom pre-11n HT), 6A:5C:35 (French drone ID) | – | As far as Wireshark 4.6.9 decodes them | P3 |
| others (e.g. Qualcomm 8C:FD:F0, Ubiquiti 00:15:6D, MediaTek, Realtek) | – | Named via OUI table, raw payload (no public or Wireshark description) | – |

Vendor decoders live in `src/ie/vendor_microsoft.cpp`, `vendor_wfa.cpp` and `vendor_misc.cpp`
(proprietary formats); sources per decoder in `docs/decoder-sources.md`.

## Derived information (summary)

| Item | Tier |
|---|---|
| Security classification incl. transition modes, PMF | P1 |
| Wi-Fi generation, band, channel, width, center frequencies | P1 |
| Max NSS and max PHY rate estimate | P1 |
| 11k/v/r roaming support | P1 |
| Device hints (WPS, vendor IEs) | P2 |
| Co-located APs (RNR), MLO links | P2 |
| Puncturing visualization data | P2 |
