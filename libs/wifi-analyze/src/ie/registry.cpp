// SPDX-License-Identifier: MIT
// Element registry: one line per known element. Entries without a decoder are only named.
// Element IDs: IEEE Std 802.11-2020 Table 9-92 (Element IDs) and amendments
// (802.11ax-2021, 802.11be-2024). Keep each table sorted by id.

#include "core/registry.hpp"

#include <algorithm>
#include <array>

#include "core/tr.hpp"
#include "ie/decoders.hpp"

namespace wifi_analyze::core {
namespace {

using namespace wifi_analyze::ie;

constexpr std::string_view std2020 = "IEEE 802.11-2020";
constexpr std::string_view std_ax = "IEEE 802.11ax-2021";
constexpr std::string_view std_be = "IEEE 802.11be-2024";
// Proprietary formats without public documentation: Wireshark is the only source.
constexpr std::string_view wireshark = "Wireshark 4.6.9 (proprietary, no public spec)";

constexpr std::array standard{
    ElementEntry{0, "ssid", WA_TR(element_ssid, "SSID"), std2020, decode_ssid},
    ElementEntry{1, "supported_rates", WA_TR(element_supported_rates, "Supported Rates"), std2020,
                 decode_supported_rates},
    ElementEntry{2, "fh_parameter_set", WA_TR(element_fh_parameter_set, "FH Parameter Set"),
                 std2020, decode_fh_parameter_set},
    ElementEntry{3, "ds_parameter_set", WA_TR(element_ds_parameter_set, "DSSS Parameter Set"),
                 std2020, decode_ds_parameter_set},
    ElementEntry{4, "cf_parameter_set", WA_TR(element_cf_parameter_set, "CF Parameter Set"),
                 std2020, decode_cf_parameter_set},
    ElementEntry{5, "tim", WA_TR(element_tim, "Traffic Indication Map (TIM)"), std2020, decode_tim},
    ElementEntry{6, "ibss_parameter_set", WA_TR(element_ibss_parameter_set, "IBSS Parameter Set"),
                 std2020, decode_ibss_parameter_set},
    ElementEntry{7, "country", WA_TR(element_country, "Country"), std2020, decode_country},
    ElementEntry{10, "request", WA_TR(element_request, "Request"), std2020, nullptr},
    ElementEntry{11, "bss_load", WA_TR(element_bss_load, "BSS Load"), std2020, decode_bss_load},
    ElementEntry{12, "edca_parameter_set", WA_TR(element_edca, "EDCA Parameter Set"), std2020,
                 decode_edca_parameter_set},
    ElementEntry{32, "power_constraint", WA_TR(element_power_constraint, "Power Constraint"),
                 std2020, decode_power_constraint},
    ElementEntry{33, "power_capability", WA_TR(element_power_capability, "Power Capability"),
                 std2020, nullptr},
    ElementEntry{35, "tpc_report", WA_TR(element_tpc_report, "TPC Report"), std2020,
                 decode_tpc_report},
    ElementEntry{36, "supported_channels", WA_TR(element_supported_channels, "Supported Channels"),
                 std2020, nullptr},
    ElementEntry{37, "channel_switch_announcement",
                 WA_TR(element_csa, "Channel Switch Announcement"), std2020,
                 decode_channel_switch_announcement},
    ElementEntry{40, "quiet", WA_TR(element_quiet, "Quiet"), std2020, decode_quiet},
    ElementEntry{41, "ibss_dfs", WA_TR(element_ibss_dfs, "IBSS DFS"), std2020, decode_ibss_dfs},
    ElementEntry{42, "erp", WA_TR(element_erp, "ERP Information"), std2020, decode_erp},
    ElementEntry{45, "ht_capabilities", WA_TR(element_ht_capabilities, "HT Capabilities"), std2020,
                 decode_ht_capabilities},
    ElementEntry{46, "qos_capability", WA_TR(element_qos_capability, "QoS Capability"), std2020,
                 decode_qos_capability},
    ElementEntry{48, "rsn", WA_TR(element_rsn, "RSN"), std2020, decode_rsn},
    ElementEntry{50, "extended_supported_rates",
                 WA_TR(element_extended_rates, "Extended Supported Rates"), std2020,
                 decode_supported_rates},
    ElementEntry{51, "ap_channel_report", WA_TR(element_ap_channel_report, "AP Channel Report"),
                 std2020, decode_ap_channel_report},
    ElementEntry{52, "neighbor_report", WA_TR(element_neighbor_report, "Neighbor Report"), std2020,
                 decode_neighbor_report},
    ElementEntry{54, "mobility_domain", WA_TR(element_mobility_domain, "Mobility Domain"), std2020,
                 decode_mobility_domain},
    ElementEntry{55, "fast_bss_transition", WA_TR(element_fte, "Fast BSS Transition"), std2020,
                 nullptr},
    ElementEntry{56, "timeout_interval", WA_TR(element_timeout_interval, "Timeout Interval"),
                 std2020, nullptr},
    ElementEntry{59, "supported_operating_classes",
                 WA_TR(element_supported_op_classes, "Supported Operating Classes"), std2020,
                 decode_supported_operating_classes},
    ElementEntry{60, "extended_channel_switch_announcement",
                 WA_TR(element_ecsa, "Extended Channel Switch Announcement"), std2020,
                 decode_extended_channel_switch_announcement},
    ElementEntry{61, "ht_operation", WA_TR(element_ht_operation, "HT Operation"), std2020,
                 decode_ht_operation},
    ElementEntry{62, "secondary_channel_offset",
                 WA_TR(element_secondary_channel_offset, "Secondary Channel Offset"), std2020,
                 decode_secondary_channel_offset},
    ElementEntry{63, "bss_average_access_delay",
                 WA_TR(element_bss_avg_access_delay, "BSS Average Access Delay"), std2020,
                 decode_bss_average_access_delay},
    ElementEntry{66, "measurement_pilot_transmission",
                 WA_TR(element_measurement_pilot, "Measurement Pilot Transmission"), std2020,
                 decode_measurement_pilot_transmission},
    ElementEntry{67, "bss_available_admission_capacity",
                 WA_TR(element_bss_admission_capacity, "BSS Available Admission Capacity"), std2020,
                 decode_bss_available_admission_capacity},
    ElementEntry{68, "bss_ac_access_delay",
                 WA_TR(element_bss_ac_access_delay, "BSS AC Access Delay"), std2020, nullptr},
    ElementEntry{69, "time_advertisement", WA_TR(element_time_advertisement, "Time Advertisement"),
                 std2020, decode_time_advertisement},
    ElementEntry{70, "rm_enabled_capabilities",
                 WA_TR(element_rm_capabilities, "RM Enabled Capabilities"), std2020,
                 decode_rm_enabled_capabilities},
    ElementEntry{71, "multiple_bssid", WA_TR(element_multiple_bssid, "Multiple BSSID"), std2020,
                 decode_multiple_bssid},
    ElementEntry{72, "bss_coexistence", WA_TR(element_coexistence, "20/40 BSS Coexistence"),
                 std2020, decode_bss_coexistence},
    ElementEntry{73, "bss_intolerant_channel_report",
                 WA_TR(element_intolerant_report, "20/40 BSS Intolerant Channel Report"), std2020,
                 decode_bss_intolerant_channel_report},
    ElementEntry{74, "obss_scan_parameters",
                 WA_TR(element_obss_scan, "Overlapping BSS Scan Parameters"), std2020,
                 decode_obss_scan_parameters},
    ElementEntry{83, "nontransmitted_bssid_capability",
                 WA_TR(element_nontx_capability, "Nontransmitted BSSID Capability"), std2020,
                 decode_nontransmitted_bssid_capability},
    ElementEntry{84, "ssid_list", WA_TR(element_ssid_list, "SSID List"), std2020, nullptr},
    ElementEntry{85, "multiple_bssid_index",
                 WA_TR(element_multiple_bssid_index, "Multiple BSSID-Index"), std2020,
                 decode_multiple_bssid_index},
    ElementEntry{90, "bss_max_idle_period", WA_TR(element_bss_max_idle, "BSS Max Idle Period"),
                 std2020, decode_bss_max_idle_period},
    ElementEntry{98, "time_zone", WA_TR(element_time_zone, "Time Zone"), std2020, decode_time_zone},
    ElementEntry{107, "interworking", WA_TR(element_interworking, "Interworking"), std2020,
                 decode_interworking},
    ElementEntry{108, "advertisement_protocol",
                 WA_TR(element_advertisement_protocol, "Advertisement Protocol"), std2020,
                 decode_advertisement_protocol},
    ElementEntry{110, "qos_map", WA_TR(element_qos_map, "QoS Map"), std2020, decode_qos_map},
    ElementEntry{111, "roaming_consortium", WA_TR(element_roaming_consortium, "Roaming Consortium"),
                 std2020, decode_roaming_consortium},
    ElementEntry{113, "mesh_configuration", WA_TR(element_mesh_configuration, "Mesh Configuration"),
                 std2020, decode_mesh_configuration},
    ElementEntry{114, "mesh_id", WA_TR(element_mesh_id, "Mesh ID"), std2020, decode_mesh_id},
    ElementEntry{127, "extended_capabilities",
                 WA_TR(element_extended_capabilities, "Extended Capabilities"), std2020,
                 decode_extended_capabilities},
    ElementEntry{133, "cisco_ccx1", WA_TR(element_cisco_ccx1, "Cisco CCX1 CKIP + Device Name"),
                 wireshark, decode_cisco_ccx1},
    ElementEntry{173, "symbol_proprietary", WA_TR(element_symbol_proprietary, "Symbol Proprietary"),
                 wireshark, decode_symbol_proprietary},
    ElementEntry{191, "vht_capabilities", WA_TR(element_vht_capabilities, "VHT Capabilities"),
                 std2020, decode_vht_capabilities},
    ElementEntry{192, "vht_operation", WA_TR(element_vht_operation, "VHT Operation"), std2020,
                 decode_vht_operation},
    ElementEntry{193, "extended_bss_load", WA_TR(element_extended_bss_load, "Extended BSS Load"),
                 std2020, decode_extended_bss_load},
    ElementEntry{194, "wide_bandwidth_channel_switch",
                 WA_TR(element_wide_bw_cs, "Wide Bandwidth Channel Switch"), std2020,
                 decode_wide_bandwidth_channel_switch},
    ElementEntry{195, "transmit_power_envelope", WA_TR(element_tpe, "Transmit Power Envelope"),
                 std2020, decode_transmit_power_envelope},
    ElementEntry{196, "channel_switch_wrapper", WA_TR(element_cs_wrapper, "Channel Switch Wrapper"),
                 std2020, decode_channel_switch_wrapper},
    ElementEntry{199, "operating_mode_notification",
                 WA_TR(element_omn, "Operating Mode Notification"), std2020,
                 decode_operating_mode_notification},
    ElementEntry{201, "reduced_neighbor_report", WA_TR(element_rnr, "Reduced Neighbor Report"),
                 std2020, decode_reduced_neighbor_report},
    ElementEntry{206, "ftm_parameters",
                 WA_TR(element_ftm_parameters, "Fine Timing Measurement Parameters"), std2020,
                 nullptr},
    ElementEntry{216, "twt", WA_TR(element_twt, "Target Wake Time"), std2020, decode_twt},
    ElementEntry{240, "fils_indication", WA_TR(element_fils_indication, "FILS Indication"), std2020,
                 decode_fils_indication},
    ElementEntry{242, "fragment", WA_TR(element_fragment, "Fragment"), std2020, nullptr},
    ElementEntry{244, "rsn_extension", WA_TR(element_rsnx, "RSN Extension"), std2020,
                 decode_rsn_extension},
};

constexpr std::array extension{
    ElementEntry{32, "password_identifier", WA_TR(element_ext_password_id, "Password Identifier"),
                 std2020, nullptr},
    ElementEntry{35, "he_capabilities", WA_TR(element_he_capabilities, "HE Capabilities"), std_ax,
                 decode_he_capabilities},
    ElementEntry{36, "he_operation", WA_TR(element_he_operation, "HE Operation"), std_ax,
                 decode_he_operation},
    ElementEntry{37, "uora_parameter_set", WA_TR(element_uora, "UORA Parameter Set"), std_ax,
                 decode_uora_parameter_set},
    ElementEntry{38, "mu_edca_parameter_set", WA_TR(element_mu_edca, "MU EDCA Parameter Set"),
                 std_ax, decode_mu_edca_parameter_set},
    ElementEntry{39, "spatial_reuse_parameter_set",
                 WA_TR(element_spatial_reuse, "Spatial Reuse Parameter Set"), std_ax,
                 decode_spatial_reuse},
    ElementEntry{41, "ndp_feedback_report_parameter_set",
                 WA_TR(element_ndp_feedback, "NDP Feedback Report Parameter Set"), std_ax,
                 decode_ndp_feedback_report_parameter_set},
    ElementEntry{42, "bss_color_change_announcement",
                 WA_TR(element_bss_color_change, "BSS Color Change Announcement"), std_ax,
                 decode_bss_color_change},
    ElementEntry{43, "quiet_time_period_setup",
                 WA_TR(element_quiet_time_period, "Quiet Time Period Setup"), std_ax, nullptr},
    ElementEntry{45, "ess_report", WA_TR(element_ess_report, "ESS Report"), std_ax,
                 decode_ess_report},
    ElementEntry{46, "ops", WA_TR(element_ops, "OPS"), std_ax, decode_ops},
    ElementEntry{47, "he_bss_load", WA_TR(element_he_bss_load, "HE BSS Load"), std_ax,
                 decode_he_bss_load},
    ElementEntry{52, "max_channel_switch_time",
                 WA_TR(element_max_cs_time, "Max Channel Switch Time"), std_ax,
                 decode_max_channel_switch_time},
    ElementEntry{55, "multiple_bssid_configuration",
                 WA_TR(element_mbssid_config, "Multiple BSSID Configuration"), std2020,
                 decode_multiple_bssid_configuration},
    ElementEntry{56, "non_inheritance", WA_TR(element_non_inheritance, "Non-Inheritance"), std2020,
                 decode_non_inheritance},
    ElementEntry{57, "known_bssid", WA_TR(element_known_bssid, "Known BSSID"), std2020, nullptr},
    ElementEntry{58, "short_ssid_list", WA_TR(element_short_ssid_list, "Short SSID List"), std2020,
                 decode_short_ssid_list},
    ElementEntry{59, "he_6ghz_band_capabilities",
                 WA_TR(element_he_6ghz_caps, "HE 6 GHz Band Capabilities"), std_ax,
                 decode_he_6ghz_band_capabilities},
    ElementEntry{60, "ul_mu_power_capabilities",
                 WA_TR(element_ul_mu_power, "UL MU Power Capabilities"), std_ax, nullptr},
    ElementEntry{106, "eht_operation", WA_TR(element_eht_operation, "EHT Operation"), std_be,
                 decode_eht_operation},
    ElementEntry{107, "multi_link", WA_TR(element_multi_link, "Multi-Link"), std_be,
                 decode_multi_link},
    ElementEntry{108, "eht_capabilities", WA_TR(element_eht_capabilities, "EHT Capabilities"),
                 std_be, decode_eht_capabilities},
    ElementEntry{109, "tid_to_link_mapping", WA_TR(element_t2lm, "TID-to-Link Mapping"), std_be,
                 decode_tid_to_link_mapping},
    ElementEntry{135, "bandwidth_indication",
                 WA_TR(element_bandwidth_indication, "Bandwidth Indication"), std_be,
                 decode_bandwidth_indication},
};

constexpr Oui oui_cisco{0x00, 0x40, 0x96};
constexpr Oui oui_aruba{0x00, 0x0b, 0x86};
constexpr Oui oui_ruckus{0x00, 0x13, 0x92};
constexpr Oui oui_mist{0x5c, 0x5b, 0x35};
constexpr Oui oui_alcatel{0xdc, 0x08, 0x56};
constexpr Oui oui_aerohive{0x00, 0x19, 0x77};
constexpr Oui oui_arista{0x00, 0x11, 0x74};
constexpr Oui oui_fortinet{0x00, 0x09, 0x0f};
constexpr Oui oui_meru{0x00, 0x0c, 0xe6};
constexpr Oui oui_zebra_extreme{0x00, 0xa0, 0xf8};
constexpr Oui oui_extreme_mesh{0x00, 0x05, 0x12};
constexpr Oui oui_mikrotik{0x00, 0x0c, 0x42};
constexpr Oui oui_atheros{0x00, 0x03, 0x7f};
constexpr Oui oui_marvell{0x00, 0x50, 0x43};
constexpr Oui oui_nintendo{0x00, 0x1f, 0x32};
constexpr Oui oui_apple{0x00, 0x17, 0xf2};
constexpr Oui oui_broadcom_pre11n{0x00, 0x90, 0x4c};
constexpr Oui oui_sgdsn{0x6a, 0x5c, 0x35};

constexpr std::array vendor{
    VendorEntry{oui_microsoft, 1, "vendor.microsoft.wpa", WA_TR(element_wpa, "WPA"),
                "Wi-Fi Alliance WPA", decode_vendor_wpa},
    VendorEntry{oui_microsoft, 2, "vendor.microsoft.wmm", WA_TR(element_wmm, "WMM"),
                "Wi-Fi Alliance WMM 1.2", decode_vendor_wmm},
    VendorEntry{oui_microsoft, 4, "vendor.microsoft.wps",
                WA_TR(element_wps, "Wi-Fi Protected Setup"), "Wi-Fi Simple Configuration 2.0",
                decode_vendor_wps},
    VendorEntry{oui_wfa, 0x09, "vendor.wfa.p2p", WA_TR(element_p2p, "Wi-Fi Direct (P2P)"),
                "Wi-Fi P2P Technical Specification", decode_vendor_p2p},
    VendorEntry{oui_wfa, 0x0a, "vendor.wfa.wfd", WA_TR(element_wfd, "Wi-Fi Display"),
                "Wi-Fi Display Technical Specification", decode_vendor_wfd},
    VendorEntry{oui_wfa, 0x10, "vendor.wfa.hs20", WA_TR(element_hs20, "Hotspot 2.0 Indication"),
                "Wi-Fi Alliance Hotspot 2.0", decode_vendor_hs20},
    VendorEntry{oui_wfa, 0x13, "vendor.wfa.nan", WA_TR(element_nan, "Wi-Fi Aware (NAN)"),
                "Wi-Fi Aware Specification", decode_vendor_nan},
    VendorEntry{oui_wfa, 0x14, "vendor.wfa.osen",
                WA_TR(element_osen, "OSEN (OSU Server-only Authenticated L2 Encryption Network)"),
                "Wi-Fi Alliance Hotspot 2.0 Release 2", decode_vendor_osen},
    VendorEntry{oui_wfa, 0x16, "vendor.wfa.mbo_oce", WA_TR(element_mbo_oce, "MBO-OCE"),
                "Wi-Fi Alliance MBO / OCE", decode_vendor_mbo_oce},
    VendorEntry{oui_wfa, 0x1a, "vendor.wfa.dpp", WA_TR(element_dpp, "Device Provisioning Protocol"),
                "Wi-Fi Easy Connect Specification", decode_vendor_dpp},
    VendorEntry{oui_wfa, 0x1b, "vendor.wfa.multi_ap",
                WA_TR(element_multi_ap, "Multi-AP (EasyMesh)"), "Wi-Fi EasyMesh Specification",
                decode_vendor_multi_ap},
    VendorEntry{oui_wfa, 0x1c, "vendor.wfa.owe_transition",
                WA_TR(element_owe_transition, "OWE Transition Mode"),
                "Wi-Fi Alliance Enhanced Open", decode_vendor_owe_transition},
    VendorEntry{oui_wfa, 0x22, "vendor.wfa.qos_mgmt", WA_TR(element_qos_mgmt, "QoS Management"),
                "Wi-Fi QoS Management Specification", decode_vendor_qos_mgmt},
    VendorEntry{oui_wfa, 0x29, "vendor.wfa.rsn_override",
                WA_TR(element_rsn_override, "RSN Element Override"),
                "Wi-Fi Alliance WPA3 Specification v3.4", decode_vendor_rsn_override},
    VendorEntry{oui_wfa, 0x2a, "vendor.wfa.rsn_override_2",
                WA_TR(element_rsn_override_2, "RSN Element Override 2"),
                "Wi-Fi Alliance WPA3 Specification v3.4", decode_vendor_rsn_override},
    VendorEntry{oui_wfa, 0x2b, "vendor.wfa.rsnx_override",
                WA_TR(element_rsnx_override, "RSN Extension Element Override"),
                "Wi-Fi Alliance WPA3 Specification v3.4", decode_vendor_rsnx_override},
    VendorEntry{oui_cisco, std::nullopt, "vendor.cisco",
                WA_TR(element_cisco, "Cisco Aironet / CCX"), wireshark, decode_vendor_cisco},
    VendorEntry{oui_aruba, std::nullopt, "vendor.aruba", WA_TR(element_aruba, "Aruba"), wireshark,
                decode_vendor_aruba},
    VendorEntry{oui_ruckus, 3, "vendor.ruckus.ap_name",
                WA_TR(element_ruckus_ap_name, "Ruckus AP Name"), wireshark,
                decode_vendor_ap_name_type},
    VendorEntry{oui_mist, 1, "vendor.mist.ap_name", WA_TR(element_mist_ap_name, "Mist AP Name"),
                wireshark, decode_vendor_ap_name_type},
    VendorEntry{oui_alcatel, 1, "vendor.alcatel_lucent.ap_name",
                WA_TR(element_alcatel_ap_name, "Alcatel-Lucent AP Name"), wireshark,
                decode_vendor_ap_name_type},
    VendorEntry{oui_aerohive, std::nullopt, "vendor.aerohive", WA_TR(element_aerohive, "Aerohive"),
                wireshark, decode_vendor_aerohive},
    VendorEntry{oui_arista, std::nullopt, "vendor.arista", WA_TR(element_arista, "Arista (Mojo)"),
                wireshark, decode_vendor_arista},
    VendorEntry{oui_fortinet, std::nullopt, "vendor.fortinet", WA_TR(element_fortinet, "Fortinet"),
                wireshark, decode_vendor_fortinet},
    VendorEntry{oui_meru, std::nullopt, "vendor.meru", WA_TR(element_meru, "Meru"), wireshark,
                decode_vendor_meru},
    VendorEntry{oui_zebra_extreme, std::nullopt, "vendor.extreme",
                WA_TR(element_extreme, "Extreme / Zebra WiNG"), wireshark, decode_vendor_extreme},
    VendorEntry{oui_extreme_mesh, std::nullopt, "vendor.extreme_mesh",
                WA_TR(element_extreme_mesh, "Extreme Mesh"), wireshark, decode_vendor_extreme_mesh},
    VendorEntry{oui_mikrotik, std::nullopt, "vendor.mikrotik", WA_TR(element_mikrotik, "MikroTik"),
                wireshark, decode_vendor_mikrotik},
    VendorEntry{oui_atheros, std::nullopt, "vendor.atheros", WA_TR(element_atheros, "Atheros"),
                wireshark, decode_vendor_atheros},
    VendorEntry{oui_marvell, std::nullopt, "vendor.marvell", WA_TR(element_marvell, "Marvell"),
                wireshark, decode_vendor_marvell},
    VendorEntry{oui_nintendo, std::nullopt, "vendor.nintendo", WA_TR(element_nintendo, "Nintendo"),
                wireshark, decode_vendor_nintendo},
    VendorEntry{oui_apple, std::nullopt, "vendor.apple", WA_TR(element_apple, "Apple"), wireshark,
                decode_vendor_apple},
    VendorEntry{oui_broadcom_pre11n, std::nullopt, "vendor.broadcom.ht",
                WA_TR(element_broadcom_ht, "Broadcom pre-802.11n HT"), wireshark,
                decode_vendor_broadcom_ht},
    VendorEntry{oui_sgdsn, std::nullopt, "vendor.sgdsn.drone_id",
                WA_TR(element_drone_id_fr, "Drone Remote ID (France)"),
                "Arrêté NOR ECOI1934044A (France)", decode_vendor_drone_id_fr},
};

template <class Table>
const ElementEntry* find_in(const Table& table, std::uint8_t id) noexcept {
    const auto* const it = std::ranges::lower_bound(table, id, {}, &ElementEntry::id);
    return it != table.end() && it->id == id ? &*it : nullptr;
}

constexpr bool sorted_by_id(const auto& table) {
    return std::ranges::is_sorted(table, {}, &ElementEntry::id) &&
           std::ranges::adjacent_find(table, {}, &ElementEntry::id) == table.end();
}
static_assert(sorted_by_id(standard), "standard element table must be sorted and unique");
static_assert(sorted_by_id(extension), "extension element table must be sorted and unique");

} // namespace

const ElementEntry* find_standard(std::uint8_t id) noexcept {
    return find_in(standard, id);
}

const ElementEntry* find_extension(std::uint8_t ext_id) noexcept {
    return find_in(extension, ext_id);
}

const VendorEntry* find_vendor(const Oui& oui, std::optional<std::uint8_t> vendor_type) noexcept {
    for (const auto& entry : vendor) {
        if (entry.oui == oui && (!entry.vendor_type || entry.vendor_type == vendor_type)) {
            return &entry;
        }
    }
    return nullptr;
}

std::span<const ElementEntry> standard_entries() noexcept {
    return standard;
}

std::span<const ElementEntry> extension_entries() noexcept {
    return extension;
}

std::span<const VendorEntry> vendor_entries() noexcept {
    return vendor;
}

} // namespace wifi_analyze::core
