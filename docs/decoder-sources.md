# Decoder sources

Where the decoding algorithm of every element decoder comes from (AGENTS.md rule 6). The same
reference is in the comment of each decoder function (`libs/wifi-analyze/src/ie/*.cpp`) and in
the `spec` string of its registry entry (`src/ie/registry.cpp`, shown by
`wifi-analyze-cli elements`).

## Rules

- **Public standards first.** IEEE 802.11 elements follow IEEE Std 802.11-2020 clause 9.4.2
  (element formats) and the amendments 802.11ax-2021 (HE) and 802.11be-2024 (EHT). Wi-Fi
  Alliance vendor elements follow the named Wi-Fi Alliance specification.
- **Cross-check:** every decoder was compared with the Wireshark **4.6.9** dissector named below
  (`epan/dissectors/packet-ieee80211.c` unless another file is given) and, where available,
  Linux `include/linux/ieee80211.h`. Wireshark is GPL: it is read as documentation only; no code
  or tables are copied.
- **Proprietary vendor elements** (no public specification) follow the Wireshark dissector only;
  their registry `spec` is "Wireshark 4.6.9 (proprietary, no public spec)". Fields that
  Wireshark does not interpret stay raw.
- Where the standard and Wireshark disagree, the standard wins and the difference is noted.

## Standard elements (Element ID)

| ID | Element | Source | Wireshark 4.6.9 |
|---|---|---|---|
| 0 | SSID | 802.11-2020 9.4.2 | `ieee80211_tag_ssid` |
| 1, 50 | Supported Rates and BSS Membership Selectors / Extended Supported Rates | 802.11-2020 9.4.2 (incl. BSS membership selector values) | `ieee80211_tag_supp_rates`, `ieee80211_tag_ext_supp_rates` |
| 2 | FH Parameter Set | 802.11-2020 9.4.2 | `ieee80211_tag_fh_parameter` |
| 3 | DSSS Parameter Set | 802.11-2020 9.4.2 | `ieee80211_tag_ds_parameter` |
| 4 | CF Parameter Set | 802.11-2020 9.4.2 | `ieee80211_tag_cf_parameter` |
| 5 | TIM | 802.11-2020 9.4.2 | `ieee80211_tag_tim` |
| 6 | IBSS Parameter Set | 802.11-2020 9.4.2 | `ieee80211_tag_ibss_parameter` |
| 7 | Country | 802.11-2020 9.4.2 (missing environment octet tolerated, see `docs/ie-coverage.md`) | `ieee80211_tag_country_info` |
| 11 | BSS Load | 802.11-2020 9.4.2 | `ieee80211_tag_qbss_load` |
| 12 | EDCA Parameter Set | 802.11-2020 9.4.2; QoS Info (AP) 9.4.1 | `ieee80211_tag_edca_param_set` |
| 32 | Power Constraint | 802.11-2020 9.4.2 | `ieee80211_tag_power_constraint` |
| 35 | TPC Report | 802.11-2020 9.4.2 | `ieee80211_tag_tpc_report` |
| 37 | Channel Switch Announcement | 802.11-2020 9.4.2 | `ieee80211_tag_switch_ann` |
| 40 | Quiet | 802.11-2020 9.4.2 | `ieee80211_tag_quiet` |
| 41 | IBSS DFS | 802.11-2020 9.4.2 (channel map bits from the standard; Wireshark shows the map raw) | `ieee80211_tag_ibss_dfs` |
| 42 | ERP | 802.11-2020 9.4.2 | `ieee80211_tag_erp_info` |
| 45 | HT Capabilities | 802.11-2020 9.4.2 | `dissect_ht_capability_ie` |
| 46 | QoS Capability (AP form) | 802.11-2020 9.4.2, 9.4.1 | `ieee80211_tag_qos_capability` |
| 48 | RSN | 802.11-2020 9.4.2 (cipher and AKM suite selector tables) | `ieee80211_tag_rsn_ie` |
| 51 | AP Channel Report | 802.11-2020 9.4.2 | `dissect_ap_channel_report` |
| 52 | Neighbor Report | 802.11-2020 9.4.2 (BSSID Information bits incl. 802.11ax/be additions; element-format subelements decoded with the element decoder) | `dissect_neighbor_report` |
| 54 | Mobility Domain | 802.11-2020 9.4.2 | `dissect_mobility_domain` |
| 59 | Supported Operating Classes | 802.11-2020 9.4.2 | `ieee80211_tag_supported_operating_classes` |
| 60 | Extended Channel Switch Announcement | 802.11-2020 9.4.2 | `ieee80211_tag_channel_switch_announcement` |
| 61 | HT Operation | 802.11-2020 9.4.2 | `dissect_ht_operation_ie` |
| 62 | Secondary Channel Offset | 802.11-2020 9.4.2 | `dissect_secondary_channel_offset_ie` |
| 63 | BSS Average Access Delay | 802.11-2020 9.4.2 | `dissect_bss_avg_access_delay_ie` |
| 66 | Measurement Pilot Transmission | 802.11-2020 9.4.2 (subelements raw) | `dissect_measurement_pilot_trans_ie` |
| 67 | BSS Available Admission Capacity | 802.11-2020 9.4.2 | `dissect_bss_available_admission_capacity_ie` |
| 69 | Time Advertisement | 802.11-2020 9.4.2 | `dissect_time_adv` |
| 70 | RM Enabled Capabilities | 802.11-2020 9.4.2 | `dissect_rm_enabled_capabilities_ie` |
| 71 | Multiple BSSID | 802.11-2020 9.4.2 | `dissect_multiple_bssid_ie` |
| 72 | 20/40 BSS Coexistence | 802.11-2020 9.4.2 | `dissect_20_40_bss_coexistence` |
| 73 | 20/40 BSS Intolerant Channel Report | 802.11-2020 9.4.2 | `dissect_20_40_bss_intolerant` |
| 74 | Overlapping BSS Scan Parameters | 802.11-2020 9.4.2 | `dissect_overlap_bss_scan_par` |
| 83 | Nontransmitted BSSID Capability | 802.11-2020 9.4.2 | `dissect_no_bssid_capability` |
| 85 | Multiple BSSID-Index | 802.11-2020 9.4.2 | `dissect_multiple_bssid_index` |
| 90 | BSS Max Idle Period | 802.11-2020 9.4.2 | `dissect_bss_max_idle_period` |
| 98 | Time Zone | 802.11-2020 9.4.2 | `dissect_time_zone` |
| 107 | Interworking | 802.11-2020 9.4.2 | `dissect_interworking` |
| 108 | Advertisement Protocol | 802.11-2020 9.4.2 | `dissect_advertisement_protocol` |
| 110 | QoS Map | 802.11-2020 9.4.2 | `dissect_qos_map_set` |
| 111 | Roaming Consortium | 802.11-2020 9.4.2 | `dissect_roaming_consortium` |
| 113 | Mesh Configuration | 802.11-2020 9.4.2 | `ieee80211_tag_mesh_configuration` |
| 114 | Mesh ID | 802.11-2020 9.4.2 | `ieee80211_tag_mesh_id` |
| 127 | Extended Capabilities | 802.11-2020 9.4.2 (+ ax/be bits) | `dissect_extended_capabilities_ie` |
| 133 | Cisco CCX1 CKIP + Device Name | proprietary | `ieee80211_tag_cisco_ccx1_ckip` |
| 173 | Symbol Proprietary (Extreme/Zebra OUI) | proprietary | `ieee80211_tag_symbol_proprietary_ie` → `dissect_symbol_proprietary_ie_extreme` |
| 191 | VHT Capabilities | 802.11-2020 9.4.2 | `dissect_vht_capability_ie` |
| 192 | VHT Operation | 802.11-2020 9.4.2 | `dissect_vht_operation_ie` |
| 193 | Extended BSS Load | 802.11-2020 9.4.2 | `dissect_ext_bss_load` |
| 194 | Wide Bandwidth Channel Switch | 802.11-2020 9.4.2 | `dissect_wide_bw_channel_switch` |
| 195 | Transmit Power Envelope | 802.11-2020 9.4.2 (+ 802.11ax PSD interpretation) | `dissect_vht_tx_pwr_envelope` |
| 196 | Channel Switch Wrapper | 802.11-2020 9.4.2 (nested elements) | `dissect_channel_switch_wrapper` |
| 199 | Operating Mode Notification | 802.11-2020 9.4.2 | `dissect_operating_mode_notification` |
| 201 | Reduced Neighbor Report | 802.11-2020 9.4.2 (+ 802.11ax/be TBTT information) | `dissect_reduced_neighbor_report` |
| 216 | Target Wake Time | 802.11ax-2021 9.4.2 (+ 802.11be link ID / aligned TWT bitmaps) | `ieee80211_tag_twt` |
| 240 | FILS Indication | 802.11-2020 9.4.2 | `ieee80211_tag_fils_indication` |
| 242 | Fragment | 802.11-2020 element fragmentation rules, handled by TLV reassembly | – |
| 244 | RSN Extension | 802.11-2020 9.4.2 (+ later bits) | `ieee80211_tag_rsnx` |

## Extension elements (Element ID 255, Element ID Extension)

| Ext | Element | Source | Wireshark 4.6.9 |
|---|---|---|---|
| 35 | HE Capabilities | 802.11ax-2021 9.4.2 | `dissect_he_capabilities` |
| 36 | HE Operation | 802.11ax-2021 9.4.2 | `dissect_he_operation` |
| 37 | UORA Parameter Set | 802.11ax-2021 9.4.2 | `dissect_uora_parameter_set` |
| 38 | MU EDCA Parameter Set | 802.11ax-2021 9.4.2 | `dissect_mu_edca_parameter_set` |
| 39 | Spatial Reuse Parameter Set | 802.11ax-2021 9.4.2 | `dissect_spatial_reuse_parameter_set` |
| 41 | NDP Feedback Report Parameter Set | 802.11ax-2021 9.4.2 | `dissect_ndp_feedback_report_set` |
| 42 | BSS Color Change Announcement | 802.11ax-2021 9.4.2 | `dissect_bss_color_change` |
| 45 | ESS Report | 802.11ax-2021 9.4.2 (threshold = −100 + value dBm, 63 = none) | `dissect_ess_report` |
| 46 | OPS | 802.11ax-2021 9.4.2 | `dissect_ops` |
| 47 | HE BSS Load | 802.11ax-2021 9.4.2 – **standard only**, Wireshark 4.6.9 names the element without decoding it | – |
| 52 | Max Channel Switch Time | 802.11ax-2021 9.4.2 | `dissect_max_channel_switch_time` |
| 55 | Multiple BSSID Configuration | 802.11-2020 9.4.2 | `dissect_multiple_bssid_configuration` |
| 56 | Non-Inheritance | 802.11-2020 9.4.2 | `dissect_non_inheritance` |
| 58 | Short SSID List | 802.11-2020 9.4.2 | `dissect_short_ssid` |
| 59 | HE 6 GHz Band Capabilities | 802.11ax-2021 9.4.2 | `dissect_he_6ghz_band_capabilities` |
| 106 | EHT Operation | 802.11be-2024 9.4.2 | `dissect_eht_operation` |
| 107 | Multi-Link (Basic) | 802.11be-2024 9.4.2 | `dissect_multi_link` |
| 108 | EHT Capabilities | 802.11be-2024 9.4.2 | `dissect_eht_capabilities` |
| 109 | TID-to-Link Mapping | 802.11be-2024 9.4.2. **Differences:** direction 0 = downlink, 1 = uplink (standard and Linux `IEEE80211_TTLM_DIRECTION_*`; Wireshark names them the other way round), and the Link Mapping Presence Indicator is absent when Default Link Mapping is set (standard, Linux; Wireshark reads it whenever the element is longer than one octet) | `dissect_tid_to_link_mapping` |
| 135 | Bandwidth Indication | 802.11be-2024 9.4.2 | `dissect_bandwidth_indication` |

## Vendor-specific elements (Element ID 221)

| OUI / type | Element | Source | Wireshark 4.6.9 |
|---|---|---|---|
| 00:50:F2 / 1 | WPA | Wi-Fi Alliance WPA (Microsoft OUI), same suite format as RSN | `dissect_vendor_ie_wpawme` |
| 00:50:F2 / 2 | WMM Information / Parameter | Wi-Fi Alliance WMM Specification 1.2 | `dissect_vendor_ie_wpawme` |
| 00:50:F2 / 4 | WPS | Wi-Fi Simple Configuration Technical Specification 2.0 (attribute list incl. WFA vendor extension, Multi-AP subelements of the EasyMesh specification) | `packet-wps.c`: `dissect_wps_tlvs`, `add_wps_wfa_ext` |
| 50:6F:9A / 0x09 | Wi-Fi Direct (P2P) | Wi-Fi P2P Technical Specification | `packet-wifi-p2p.c`: `dissect_wifi_p2p_ie` |
| 50:6F:9A / 0x0A | Wi-Fi Display | Wi-Fi Display Technical Specification (device information decoded, other subelements raw) | `packet-wifi-display.c`: `dissect_wifi_display_ie` |
| 50:6F:9A / 0x10 | Hotspot 2.0 Indication | Wi-Fi Alliance Hotspot 2.0 Specification | `dissect_hs20_indication` |
| 50:6F:9A / 0x13 | Wi-Fi Aware (NAN) | Wi-Fi Aware Specification (attribute list, attributes raw) | `packet-wifi-nan.c`: `dissect_nan_beacon` |
| 50:6F:9A / 0x14 | OSEN | Wi-Fi Alliance Hotspot 2.0 Release 2 (RSN body without version) | `dissect_hs20_osen` |
| 50:6F:9A / 0x16 | MBO-OCE | Wi-Fi Alliance MBO and OCE specifications | `dissect_mbo_oce` |
| 50:6F:9A / 0x1A | DPP | Wi-Fi Easy Connect Specification; body shown raw (as Wireshark) | `packet-wifi-dpp.c`: `dissect_wifi_dpp_ie` |
| 50:6F:9A / 0x1B | Multi-AP (EasyMesh) | Wi-Fi EasyMesh Specification | `packet-wps.c`: `dissect_wps_wfa_ext_via_dt` |
| 50:6F:9A / 0x1C | OWE Transition Mode | Wi-Fi Alliance Enhanced Open / OWE | `dissect_owe_transition_mode` |
| 50:6F:9A / 0x22 | QoS Management | Wi-Fi QoS Management Specification (attribute list) | `dissect_qos_mgmt` |
| 50:6F:9A / 0x29, 0x2A | RSN Element Override (2) | Wi-Fi Alliance WPA3 Specification v3.4 (RSN body, decoded by the RSN decoder; not used for the summary) | `dissect_wfa_rsn_override(_2)` |
| 50:6F:9A / 0x2B | RSNX Override | Wi-Fi Alliance WPA3 Specification v3.4 (RSNX body) | `dissect_wfa_rsnx_override` |
| 00:40:96 | Cisco Aironet / CCX (DTPC, CCX version, QoS, QBSS v2, client MFP, AP name v2) | proprietary | `dissect_vendor_ie_aironet` |
| 00:0B:86 | Aruba (AP name, GPS ellipse) | proprietary | `dissect_vendor_ie_aruba` |
| 00:13:92 / 3 | Ruckus AP name | proprietary | `dissect_vendor_ie_ruckus` |
| 5C:5B:35 / 1 | Mist AP name | proprietary | `dissect_vendor_ie_mist` |
| DC:08:56 / 1 | Alcatel-Lucent AP name | proprietary | `dissect_vendor_ie_alcatel` |
| 00:19:77 | Aerohive (host name) | proprietary | `dissect_vendor_ie_aerohive` |
| 00:11:74 | Arista / Mojo (AP name) | proprietary | `dissect_vendor_ie_arista` |
| 00:09:0F | Fortinet (AP name, model, serial) | proprietary | `dissect_vendor_ie_fortinet` |
| 00:0C:E6 | Meru (TLVs, raw) | proprietary | `dissect_vendor_ie_meru` |
| 00:A0:F8 | Extreme / Zebra WiNG (AP name) | proprietary | `dissect_vendor_ie_extreme` |
| 00:05:12 | Extreme mesh (hello, mesh ID, MPID) | proprietary | `dissect_vendor_ie_extreme_mesh` |
| 00:0C:42 | MikroTik / RouterBOARD (identity) | proprietary | `dissect_vendor_ie_routerboard` |
| 00:03:7F | Atheros (advanced capability, XR) | proprietary | `dissect_vendor_ie_atheros` |
| 00:50:43 | Marvell (mesh) | proprietary | `dissect_vendor_ie_marvell` |
| 00:1F:32 | Nintendo (StreetPass services, console ID) | proprietary | `dissect_vendor_ie_nintendo` |
| 00:17:F2 | Apple (type/subtype only, body raw) | proprietary | `dissect_vendor_ie_apple` |
| 00:90:4C / 51, 52 | Broadcom pre-802.11n HT Capabilities / Information | IEEE 802.11n draft 1.0 = HT element layouts | `dissect_vendor_ie_ht` |
| 6A:5C:35 / 1 | Drone remote ID (France) | French arrêté NOR ECOI1934044A (27 Dec 2019) | `dissect_vendor_ie_sgdsn` |

## Not decoded (named only), and why

The input of this project is beacon / probe response data, so only elements that occur there
are decoded. Remaining named-only entries:

- **Frame-exchange-only elements**: Request, Power Capability, Supported Channels, Fast BSS
  Transition, Timeout Interval, SSID List, Known BSSID, UL MU Power Capabilities, Password
  Identifier, FTM Parameters, Quiet Time Period Setup – they appear in (re)association,
  authentication or action frames, never in beacons.
- **Element 68**: the ID is assigned twice (BSS AC Access Delay in 802.11 and WAPI parameter set
  in the Chinese WAPI standard); the format cannot be chosen reliably (Wireshark:
  `ieee80211_tag_ie_68_conflict`).
- **DMG (60 GHz, 802.11ad/ay) and S1G (sub-1 GHz, 802.11ah) elements**: not supported by the
  scanning hardware this project targets.
- **Vendor dissectors in Wireshark that are not used here**: `dissect_vendor_ie_rsn`
  (00:0F:AC KDEs, EAPOL key data only), `dissect_vendor_ie_wisun` (Wi-SUN FAN KDEs, EAPOL only),
  WFA subtypes 0x00/0x01 (Hotspot 2.0 WNM action frames), 0x17 (60 GHz), 0x20 (Transition
  Disable KDE), 0x2C/0x2D (RSN selection / override link KDE, association and EAPOL frames).
- **Vendor elements without any public or Wireshark description** (e.g. Qualcomm 8C:FD:F0,
  Ubiquiti 00:15:6D, MediaTek, Realtek): shown with the vendor name from the OUI table and raw
  content.
