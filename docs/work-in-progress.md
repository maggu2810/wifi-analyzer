# Work in progress – decoder extension (handoff)

Status 2026-10-26. Task from the maintainer:

1. Add a FILS Indication decoder.
2. Implement every decoder whose format is publicly available (IEEE 802.11 + amendments,
   Wi-Fi Alliance specs).
3. Implement the vendor decoders that upstream Wireshark has.
4. Document the sources of every decoding algorithm.

Nothing of this is implemented yet (no code changes since commit `3060af0`).

## Decisions taken

- **Scope of (2):** only elements that can appear in beacons / probe responses (= the only
  input of this project). Frame-exchange-only elements (TSPEC, TCLAS, RIC, MMIE, MIC,
  Measurement Request/Report, TFS, WNM Sleep, Link Identifier, Wakeup Schedule, Challenge
  Text, Timeout Interval, FTE, Power Capability, Supported Channels, SSID List, Known BSSID,
  UL MU Power, SAE elements) and DMG (60 GHz) / S1G (sub-1 GHz) elements stay named-only;
  document this with the reason in `docs/decoder-sources.md`.
- **Reference implementation:** Wireshark **v4.6.9** (latest stable; 4.7.x is the
  development branch), files `epan/dissectors/packet-ieee80211.c`, `packet-ieee80211.h`,
  `packet-wps.c`. Download them into the scratchpad; **read only, never copy code** (GPL).
  `https://gitlab.com/wireshark/wireshark/-/raw/v4.6.9/epan/dissectors/<file>`
- **Sources doc (4):** new `docs/decoder-sources.md`: one row per decoder (ours, existing and
  new): element/ext/OUI → standard document + element name, plus the Wireshark 4.6.9
  function name as cross-reference; vendor decoders: Wireshark function as the only source.
  Also put the reference into the code comment of each decoder.
- **Versioning (AGENTS.md):** new decoders = library MINOR → lib `0.2.0`; CLI and app bump
  PATCH (`0.1.1`, app `versionCode 2`); add `CHANGELOG.md` entries. Docs-only commits do
  not bump.
- Undecodable vendor IEs from the maintainer's APs: Qualcomm `8c:fd:f0` (types 1, 4) and
  Ubiquiti `00:15:6d` (type 0) have **no** Wireshark dissector → stay raw. Atheros
  `00:03:7f` is in Wireshark (`dissect_vendor_ie_atheros`).

## Layouts already extracted from Wireshark 4.6.9 (verified)

All little-endian unless noted.

| Element | Wireshark function | Layout |
|---|---|---|
| 240 FILS Indication | `ieee80211_tag_fils_indication` | u16 info: B0-2 #public keys, B3-5 #realms, B6 IP address configuration, B7 cache id included, B8 HESSID included, B9 FILS SK auth w/o PFS, B10 FILS SK auth with PFS, B11 FILS public key auth, B12-15 reserved; then [cache id 2 octets] [HESSID 6] [realm ids 2 octets each] [public keys: type u8, length u8, indicator *length*] (key type names unknown → numeric) |
| 2 FH Parameter Set | `ieee80211_tag_fh_parameter` | dwell time u16 (TU), hop set u8, hop pattern u8, hop index u8 |
| 4 CF Parameter Set | `ieee80211_tag_cf_parameter` | CFP count u8, CFP period u8, CFP max duration u16 (TU), CFP duration remaining u16 (TU); length 6 |
| 12 EDCA Parameter Set | `ieee80211_tag_edca_param_set` → `decode_qos_parameter_set` | length 18: QoS Info u8 (AP: B0-3 EDCA param set update count, B4 Q-Ack, B5 Queue Request, B6 TXOP Request, B7 More Data Ack), reserved u8, 4 AC records exactly like WMM (reuse `decode_edca_records`) |
| 41 IBSS DFS | `ieee80211_tag_ibss_dfs` | DFS owner MAC (6), recovery interval u8, then pairs (channel u8, map u8) to the end; map bits per standard: B0 BSS, B1 OFDM preamble, B2 unidentified signal, B3 radar, B4 unmeasured (Wireshark shows map raw) |
| 46 QoS Capability | `ieee80211_tag_qos_capability` → `add_ff_qos_info_ap` | u8, AP form: B0-3 EDCA update count, B4 Q-Ack, B5 Queue Request, B6 TXOP Request, B7 More Data Ack |
| 62 Secondary Channel Offset | `dissect_secondary_channel_offset_ie` | u8: 0 none, 1 above, 3 below (same names as HT op) |
| 63 BSS Average Access Delay | `dissect_bss_avg_access_delay_ie` | u8 AP average access delay |
| 66 Measurement Pilot Transmission | `dissect_measurement_pilot_trans_ie` | u8 measurement pilot interval (TU), then subelements (id u8, len u8, data) |
| 67 BSS Available Admission Capacity | `dissect_bss_available_admission_capacity_ie` | u16 bitmask (B0-7 UP0-7, B8-11 AC0-3, rest reserved), then one u16 (units of 32 µs/s) per set bit in that order |
| 68 | `ieee80211_tag_ie_68_conflict` | ambiguous (BSS AC Access Delay vs. WAPI) → keep named-only, document why |
| 69 Time Advertisement | `dissect_time_adv` | timing capabilities u8; if 1: time value (10) + time error (5); if 2: time value = year u16, month u8, day u8, hours u8, minutes u8, seconds u8, milliseconds u16, reserved u8 (10 octets) + time error (5) + time update counter u8 |
| 73 20/40 BSS Intolerant Channel Report | `dissect_20_40_bss_intolerant` | operating class u8, channel list u8… |
| 90 BSS Max Idle Period | `dissect_bss_max_idle_period` | max idle period u16 (units of 1000 TU), options u8 (B0 protected keep-alive required) |
| 98 Time Zone | `dissect_time_zone` | ASCII string (whole content) |
| 110 QoS Map | `dissect_qos_map_set` | length ≥ 16 and even; (length-16)/2 DSCP exceptions (DSCP u8 ≤63, UP u8 ≤7), then 8 DSCP ranges (low u8, high u8) for UP0..7; 255/255 = unused |
| 193 Extended BSS Load | `dissect_ext_bss_load` | MU-MIMO capable STA count u16, spatial stream underutilization u8, observable secondary 20/40/80 MHz utilization u8 each (x/255) |
| 194 Wide Bandwidth Channel Switch | `dissect_wide_bw_channel_switch` | new channel width u8, CCFS0 u8, CCFS1 u8 |
| 196 Channel Switch Wrapper | `dissect_channel_switch_wrapper` | nested elements (New Country 7, Wide BW CS 194, TPE 195, ext Bandwidth Indication 135) → `nested_elements()` |
| 216 TWT | `ieee80211_tag_twt` | control u8: B0 NDP paging indicator, B1 responder PM mode, B2-3 negotiation type (0 individual, 1 wake TBTT, 2 broadcast in broadcast frame, 3 broadcast in unicast frame), B4 TWT info frame disabled, B5 wake duration unit (1 = 1 TU, 0 = 256 µs), B6 link ID bitmap present, B7 aligned TWT. **Broadcast** (neg type bit 1 set): repeated parameter sets until "last": request type u16 (B0 requester, B1-3 setup command, B4 trigger, B5 last broadcast parameter set, B6 flow type (1 = unannounced), B7-9 broadcast TWT recommendation, B10-14 wake interval exponent, B15 aligned), target wake time u16, nominal min wake duration u8, wake interval mantissa u16, broadcast info u16 (B0 restricted TWT traffic info present, B1-2 RTWT schedule info, B3-7 broadcast TWT ID, B8-15 persistence), [if B0: traffic info control u8 (B0 DL TID bitmap valid, B1 UL valid), DL bitmap u8, UL bitmap u8]. **Individual**: request type u16 (B0 requester, B1-3 setup cmd, B4 trigger, B5 implicit, B6 flow type, B7-9 flow ID, B10-14 wake interval exponent, B15 protection), target wake time u64, nominal min wake duration u8, mantissa u16, channel u8, [NDP paging u32 if ctrl B0], [link ID bitmap u16 if ctrl B6], [aligned TWT link bitmap u16 if ctrl B7]. Setup commands: 0 Request, 1 Suggest, 2 Demand, 3 Grouping, 4 Accept, 5 Alternate, 6 Dictate, 7 Reject |
| ext 37 UORA Parameter Set | `dissect_uora_parameter_set` | u8 (per standard: B0-2 EOCWmin, B3-5 EOCWmax) – Wireshark field mask not yet confirmed, check `hf_ieee80211_he_uora_*` |
| ext 41 NDP Feedback Report Parameter Set | `dissect_ndp_feedback_report_set` | u8 resource request buffer threshold exponent |
| ext 45 ESS Report | `dissect_ess_report` | u8: B0-1 ESS information (B0 planned ESS, B1 edge of ESS – confirm names), B2-7 recommended BSS transition RSSI threshold (63 = no recommendation; Wireshark: signed, check the formula in `dissect_ess_report`) |
| ext 46 OPS | `dissect_ops` | OPS duration u8 (ms) |
| ext 47 HE BSS Load | – (named only in Wireshark) | standard (802.11ax): HE STA count u16, utilization u8, frequency underutilization u8, spatial stream underutilization u8 – no second source; mark as such |
| ext 52 Max Channel Switch Time | `dissect_max_channel_switch_time` | u24 switch time (TU) |
| ext 109 TID-to-Link Mapping | `dissect_tid_to_link_mapping` | control u8 (B3 switch time present → u16, B4 expected duration present → u24, B5 link mapping presence indicator present → presence u8 then one map per set bit; map size per control bit) – read the function again for exact bits |
| ext 135 Bandwidth Indication | `dissect_bandwidth_indication` | parameters u8 (B1 disabled subchannel bitmap present), control u8 (channel width B0-2 like EHT op), CCFS0 u8, CCFS1 u8, [disabled subchannel bitmap u16] |

Not yet extracted: Neighbor Report (52, `dissect_neighbor_report`, lines ~11696-11813),
Mesh Channel Switch / Awake Window / Beacon Timing (mesh beacons), and all vendor dissectors.

## Vendor dissectors in Wireshark 4.6.9 (`ieee80211_tag_vendor_specific_ie`)

To implement (read each function, then the `hf_` field definitions for masks/units):

| OUI constant | Function (line in 4.6.9) |
|---|---|
| CISCOWL 00:40:96 (Aironet/CCX) | `dissect_vendor_ie_aironet` (21251) |
| MARVELL | `dissect_vendor_ie_marvell` (20967) |
| ATHEROS 00:03:7f | `dissect_vendor_ie_atheros` (21117) |
| EXTREME_MESH | `dissect_vendor_ie_extreme_mesh` (21065) |
| ARUBA 00:0b:86 | `dissect_vendor_ie_aruba` (21366) |
| NINTENDO | `dissect_vendor_ie_nintendo` (21867) |
| ROUTERBOARD (MikroTik 00:0c:42) | `dissect_vendor_ie_routerboard` (21480) |
| MERU | `dissect_vendor_ie_meru` (21922) |
| ZEBRA_EXTREME | `dissect_vendor_ie_extreme` (21963), also element 173 Symbol proprietary (`dissect_symbol_proprietary_ie_extreme`) |
| AEROHIVE | `dissect_vendor_ie_aerohive` (21539) |
| MIST | `dissect_vendor_ie_mist` (21589) |
| RUCKUS 00:13:92 | `dissect_vendor_ie_ruckus` (21620) |
| ALCATEL_LUCENT | `dissect_vendor_ie_alcatel` (21651) |
| SGDSN (French drone ID) | `dissect_vendor_ie_sgdsn` (21706) |
| FORTINET | `dissect_vendor_ie_fortinet` (22018) |
| MOJO_ARISTA | `dissect_vendor_ie_arista` (22086) |
| WISUN | `dissect_vendor_ie_wisun` (22156) |
| APPLE 00:17:f2 | `dissect_vendor_ie_apple` (22220) |
| PRE11N (00:90:4c, Broadcom pre-802.11n HT) | `dissect_vendor_ie_ht` |
| RSN OUI 00:0f:ac as vendor IE | `dissect_vendor_ie_rsn` |
| WFA 50:6f:9a | `dissect_vendor_ie_wfa` (20698) – compare its subtypes with ours (P2P, HS2.0, MBO-OCE, OWE): e.g. OSEN, WFD, NAN, DPP, … |
| Microsoft WPS | `packet-wps.c` – compare attribute list with ours |

Add the OUIs to `libs/wifi-analyze/data/oui-builtin.csv` (values from the `OUI_*` defines in
Wireshark's `epan/oui.h`, which still needs to be downloaded).

## Remaining steps

1. Download Wireshark 4.6.9 sources to the scratchpad again (they are not in the repo).
2. Implement the standard elements above (new file `src/ie/standard_more.cpp`), register
   in `src/ie/registry.cpp`, add `WA_TR` labels, unit tests with byte vectors, update
   `docs/ie-coverage.md`. Commit with version bumps (lib 0.2.0, CLI 0.1.1, app 0.1.1/vc 2).
3. Extract and implement the vendor dissectors (`src/ie/vendor_<name>.cpp`), tests,
   commit (lib 0.3.0, CLI 0.1.2, app 0.1.2/vc 3).
4. Write `docs/decoder-sources.md` (all decoders, incl. the existing ones) and add the
   source reference to every decoder comment; link from `docs/README.md` and `AGENTS.md`
   rule 6.
5. Regenerate golden files if output changed, run dev/asan/tidy/NDK builds, fuzzers,
   Android build + tests; update `CHANGELOG.md`.
6. Delete this file when done.
