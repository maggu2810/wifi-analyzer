// SPDX-License-Identifier: MIT
#pragma once

// Element decoder functions, registered in src/ie/registry.cpp.

#include <wifi_analyze/elements.hpp>

#include "core/decoder.hpp"

namespace wifi_analyze::ie {

using core::Decoder;

// standard_basic.cpp
ElementValue decode_ssid(Decoder& d);
ElementValue decode_supported_rates(Decoder& d);
ElementValue decode_ds_parameter_set(Decoder& d);
ElementValue decode_tim(Decoder& d);
ElementValue decode_ibss_parameter_set(Decoder& d);
ElementValue decode_country(Decoder& d);
ElementValue decode_bss_load(Decoder& d);
ElementValue decode_power_constraint(Decoder& d);
ElementValue decode_tpc_report(Decoder& d);
ElementValue decode_channel_switch_announcement(Decoder& d);
ElementValue decode_quiet(Decoder& d);
ElementValue decode_erp(Decoder& d);
ElementValue decode_ap_channel_report(Decoder& d);
ElementValue decode_mobility_domain(Decoder& d);
ElementValue decode_supported_operating_classes(Decoder& d);
ElementValue decode_extended_channel_switch_announcement(Decoder& d);
ElementValue decode_rm_enabled_capabilities(Decoder& d);
ElementValue decode_bss_coexistence(Decoder& d);
ElementValue decode_obss_scan_parameters(Decoder& d);
ElementValue decode_interworking(Decoder& d);
ElementValue decode_advertisement_protocol(Decoder& d);
ElementValue decode_roaming_consortium(Decoder& d);
ElementValue decode_mesh_configuration(Decoder& d);
ElementValue decode_mesh_id(Decoder& d);
ElementValue decode_transmit_power_envelope(Decoder& d);
ElementValue decode_operating_mode_notification(Decoder& d);
ElementValue decode_extended_capabilities(Decoder& d);

// ht_vht.cpp
ElementValue decode_ht_capabilities(Decoder& d);
ElementValue decode_ht_operation(Decoder& d);
ElementValue decode_vht_capabilities(Decoder& d);
ElementValue decode_vht_operation(Decoder& d);

// rsn.cpp
ElementValue decode_rsn(Decoder& d);
ElementValue decode_rsn_extension(Decoder& d);

// mbssid_rnr.cpp
ElementValue decode_multiple_bssid(Decoder& d);
ElementValue decode_nontransmitted_bssid_capability(Decoder& d);
ElementValue decode_multiple_bssid_index(Decoder& d);
ElementValue decode_reduced_neighbor_report(Decoder& d);

// he.cpp
ElementValue decode_he_capabilities(Decoder& d);
ElementValue decode_he_operation(Decoder& d);
ElementValue decode_mu_edca_parameter_set(Decoder& d);
ElementValue decode_spatial_reuse(Decoder& d);
ElementValue decode_bss_color_change(Decoder& d);
ElementValue decode_multiple_bssid_configuration(Decoder& d);
ElementValue decode_non_inheritance(Decoder& d);
ElementValue decode_short_ssid_list(Decoder& d);
ElementValue decode_he_6ghz_band_capabilities(Decoder& d);

// eht.cpp
ElementValue decode_eht_operation(Decoder& d);
ElementValue decode_eht_capabilities(Decoder& d);
ElementValue decode_multi_link(Decoder& d);

// vendor_microsoft.cpp (reader positioned after the OUI)
ElementValue decode_vendor_wpa(Decoder& d);
ElementValue decode_vendor_wmm(Decoder& d);
ElementValue decode_vendor_wps(Decoder& d);

// vendor_wfa.cpp (reader positioned after the OUI)
ElementValue decode_vendor_p2p(Decoder& d);
ElementValue decode_vendor_hs20(Decoder& d);
ElementValue decode_vendor_mbo_oce(Decoder& d);
ElementValue decode_vendor_owe_transition(Decoder& d);

// Shared helpers (rsn.cpp): cipher and AKM suite names.
Text cipher_suite_name(const Suite& suite);
Text akm_suite_name(const Suite& suite);
/// Reads a suite selector (OUI + type) and adds it with its name.
std::optional<Suite> read_suite(Decoder& d, TreeNode& parent, MessageId label, bool akm);
/// Reads "count (u16) + count suites" as a group node.
std::vector<Suite> read_suite_list(Decoder& d, MessageId label, bool akm);

// standard_basic.cpp: Interworking access network type names.
Text access_network_type_name(std::uint64_t value);

// ht_vht.cpp: adds a 16-bit VHT/HE-style MCS map (2 bits per spatial stream 1..8).
void add_mcs_map(Decoder& d, TreeNode& parent, MessageId label, core::NameFn names);

// he.cpp: shared EDCA access-category record names and the 4-record EDCA parameter list
// (with TXOP limit) used by the WMM Parameter element.
Text access_category_name(std::uint64_t aci);
std::vector<WmmAc> decode_edca_records(Decoder& d, TreeNode& parent);

} // namespace wifi_analyze::ie
