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

// standard_more.cpp
ElementValue decode_fh_parameter_set(Decoder& d);
ElementValue decode_cf_parameter_set(Decoder& d);
ElementValue decode_edca_parameter_set(Decoder& d);
ElementValue decode_ibss_dfs(Decoder& d);
ElementValue decode_qos_capability(Decoder& d);
ElementValue decode_secondary_channel_offset(Decoder& d);
ElementValue decode_bss_average_access_delay(Decoder& d);
ElementValue decode_measurement_pilot_transmission(Decoder& d);
ElementValue decode_bss_available_admission_capacity(Decoder& d);
ElementValue decode_time_advertisement(Decoder& d);
ElementValue decode_bss_intolerant_channel_report(Decoder& d);
ElementValue decode_bss_max_idle_period(Decoder& d);
ElementValue decode_time_zone(Decoder& d);
ElementValue decode_qos_map(Decoder& d);
ElementValue decode_extended_bss_load(Decoder& d);
ElementValue decode_wide_bandwidth_channel_switch(Decoder& d);
ElementValue decode_channel_switch_wrapper(Decoder& d);
ElementValue decode_neighbor_report(Decoder& d);
ElementValue decode_twt(Decoder& d);
ElementValue decode_fils_indication(Decoder& d);
ElementValue decode_uora_parameter_set(Decoder& d);
ElementValue decode_ndp_feedback_report_parameter_set(Decoder& d);
ElementValue decode_ess_report(Decoder& d);
ElementValue decode_ops(Decoder& d);
ElementValue decode_he_bss_load(Decoder& d);
ElementValue decode_max_channel_switch_time(Decoder& d);
ElementValue decode_tid_to_link_mapping(Decoder& d);
ElementValue decode_bandwidth_indication(Decoder& d);

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
ElementValue decode_vendor_osen(Decoder& d);
ElementValue decode_vendor_wfd(Decoder& d);
ElementValue decode_vendor_nan(Decoder& d);
ElementValue decode_vendor_dpp(Decoder& d);
ElementValue decode_vendor_multi_ap(Decoder& d);
ElementValue decode_vendor_qos_mgmt(Decoder& d);
ElementValue decode_vendor_rsn_override(Decoder& d);
ElementValue decode_vendor_rsnx_override(Decoder& d);
ElementValue decode_vendor_wfa_capabilities(Decoder& d);
/// Adds a WFA vendor-extension / Multi-AP subelement (ids 0x05-0x08) to `parent`; `start` is
/// the content offset of the subelement header. Returns false for other ids / lengths.
bool multi_ap_subelement(TreeNode& parent, std::uint8_t id, std::span<const std::uint8_t> v,
                         std::size_t start);

// vendor_misc.cpp (proprietary; reader positioned after the OUI unless noted)
ElementValue decode_vendor_cisco(Decoder& d);
ElementValue decode_cisco_ccx1(Decoder& d);         // element 133
ElementValue decode_symbol_proprietary(Decoder& d); // element 173, starts with the OUI
ElementValue decode_vendor_aruba(Decoder& d);
ElementValue decode_vendor_ap_name_type(Decoder& d);
ElementValue decode_vendor_aerohive(Decoder& d);
ElementValue decode_vendor_arista(Decoder& d);
ElementValue decode_vendor_huawei(Decoder& d);
ElementValue decode_vendor_fortinet(Decoder& d);
ElementValue decode_vendor_meru(Decoder& d);
ElementValue decode_vendor_extreme(Decoder& d);
ElementValue decode_vendor_extreme_mesh(Decoder& d);
ElementValue decode_vendor_mikrotik(Decoder& d);
ElementValue decode_vendor_atheros(Decoder& d);
ElementValue decode_vendor_marvell(Decoder& d);
ElementValue decode_vendor_nintendo(Decoder& d);
ElementValue decode_vendor_apple(Decoder& d);
ElementValue decode_vendor_broadcom_ht(Decoder& d);
ElementValue decode_vendor_drone_id_fr(Decoder& d);

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
