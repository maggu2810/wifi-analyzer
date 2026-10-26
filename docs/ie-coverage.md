# IE coverage plan

Priority tiers:

- **P1** – milestone M1, required for a useful summary (security, PHY, channel).
- **P2** – M1/M2 stretch, commonly seen in beacons and interesting to show.
- **P3** – later; rare or very complex. Until decoded they appear as raw + named.

**Status (M1):** all P1 elements and most P2 elements are decoded; `wifi-analyze-cli elements`
prints the authoritative list (decoded vs. named-only). Not yet decoded: TWT (216), FILS
Indication (240), UORA, NDP Feedback, ESS Report, HE BSS Load, TID-to-Link Mapping, Neighbor
Report, Time Advertisement, QoS Map, vendor elements other than Microsoft/WFA.

Every element that is not decoded is still **named** (from the full Element ID table)
and kept raw. The "Spec" column is filled in during implementation with the exact
clause of IEEE 802.11-2024 (or the amendment / vendor spec).

> ⚠️ The tables in `old/wifi-ie-parser/README.md` contain errors (e.g. HE 6 GHz Band
> Capabilities is Ext ID **59**, not 106; Ext 106/107/108 are EHT Operation / Multi-Link /
> EHT Capabilities; Element 240 is **FILS Indication**, not proprietary). Every ID below
> is to be re-verified against the standard / Linux `ieee80211.h` / Wireshark during
> implementation.

## Standard elements

| ID | Name | Tier | Notes |
|---|---|---|---|
| 0 | SSID | P1 | Detect hidden (len 0 or zero-filled); non-UTF-8 shown escaped |
| 1 | Supported Rates | P1 | Basic-rate flag, BSS membership selectors (HT/VHT/HE/SAE-H2E) |
| 3 | DSSS Parameter Set | P1 | Current channel |
| 5 | TIM | P2 | DTIM count/period, bitmap |
| 7 | Country | P1 | Country code, environment, triplets / operating-class triplets |
| 11 | BSS Load | P1 | Stations, utilization %, admission capacity |
| 32 | Power Constraint | P2 | |
| 35 | TPC Report | P2 | |
| 37 | Channel Switch Announcement | P2 | |
| 40 | Quiet | P3 | |
| 42 | ERP Information | P2 | |
| 45 | HT Capabilities | P1 | Full cap info, A-MPDU params, MCS set, ext caps, TxBF, ASEL |
| 48 | RSN | P1 | Ciphers, AKMs (full suite table), capabilities, PMKID, group mgmt cipher |
| 50 | Extended Supported Rates | P1 | Merged with ID 1 in summary |
| 51 | AP Channel Report | P2 | |
| 54 | Mobility Domain | P1 | 802.11r detection |
| 59 | Supported Operating Classes | P2 | |
| 61 | HT Operation | P1 | Primary channel, secondary offset, protection |
| 69 | Time Advertisement | P3 | |
| 70 | RM Enabled Capabilities | P1 | 802.11k bits |
| 71 | Multiple BSSID | P2 | Non-transmitted BSSID profiles (recursive) |
| 72 | 20/40 BSS Coexistence | P2 | |
| 74 | Overlapping BSS Scan Params | P3 | |
| 107 | Interworking | P2 | Access network type, internet, ASRA, HESSID |
| 108 | Advertisement Protocol | P2 | ANQP |
| 111 | Roaming Consortium | P2 | |
| 113 / 114 | Mesh Configuration / Mesh ID | P3 | |
| 127 | Extended Capabilities | P1 | Full bit table (BSS transition/11v, interworking, TWT, FTM, …) |
| 191 | VHT Capabilities | P1 | Incl. MCS/NSS maps |
| 192 | VHT Operation | P1 | Channel width, center segments |
| 195 | Transmit Power Envelope | P2 | |
| 199 | Operating Mode Notification | P2 | |
| 201 | Reduced Neighbor Report | P2 | TBTT info → co-located (6 GHz) APs |
| 240 | FILS Indication | P3 | |
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
| 42 | BSS Color Change Announcement | P3 |
| 55 | Multiple BSSID Configuration | P2 |
| 56 | Non-Inheritance | P3 |
| 58 | Short SSID List | P3 |
| 59 | HE 6 GHz Band Capabilities | P1 |
| 106 | EHT Operation | P1 (width incl. 320 MHz, disabled subchannel bitmap / puncturing) |
| 107 | Multi-Link | P2 (basic variant first, per-STA profiles) |
| 108 | EHT Capabilities | P1 |
| 109 | TID-To-Link Mapping | P3 |

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
| 00:40:96 (Cisco) | various | Cisco CCX / AP name | P3 |
| 00:0C:42 (MikroTik) | – | Router/identity name | P3 |
| 00:10:18 (Broadcom), 00:03:7F (Qualcomm), 00:0C:E7 (MediaTek), 00:17:F2 (Apple), 00:0B:86 (Aruba), … | – | Named via OUI table, raw payload | P2 (naming only) |

Vendor decoders live in `src/vendor/<vendor>.cpp`, one file per OUI.

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
