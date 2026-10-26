// SPDX-License-Identifier: MIT
// Extended Capabilities element (127). Reference: IEEE Std 802.11-2020, Extended Capabilities
// field (Table 9-153), plus later amendments as used by hostapd / Linux (TWT, beacon protection,
// SAE password identifiers, EMA, MSCS).
// Cross-checked with Wireshark 4.6.9 packet-ieee80211.c; the dissector per element is listed in
// docs/decoder-sources.md.

#include <algorithm>
#include <array>

#include "ie/decoders.hpp"

namespace wifi_analyze::ie {
namespace {

struct CapabilityBit {
    std::uint16_t bit;
    MessageId label;
};

constexpr std::array known_bits{
    CapabilityBit{0, WA_TR(extcap_2040_coexistence, "20/40 BSS Coexistence Management Support")},
    CapabilityBit{2, WA_TR(extcap_extended_channel_switching, "Extended Channel Switching")},
    CapabilityBit{4, WA_TR(extcap_psmp, "PSMP Capability")},
    CapabilityBit{6, WA_TR(extcap_spsmp, "S-PSMP Support")},
    CapabilityBit{7, WA_TR(extcap_event, "Event")},
    CapabilityBit{8, WA_TR(extcap_diagnostics, "Diagnostics")},
    CapabilityBit{9, WA_TR(extcap_multicast_diagnostics, "Multicast Diagnostics")},
    CapabilityBit{10, WA_TR(extcap_location_tracking, "Location Tracking")},
    CapabilityBit{11, WA_TR(extcap_fms, "FMS")},
    CapabilityBit{12, WA_TR(extcap_proxy_arp, "Proxy ARP Service")},
    CapabilityBit{13, WA_TR(extcap_collocated_interference, "Collocated Interference Reporting")},
    CapabilityBit{14, WA_TR(extcap_civic_location, "Civic Location")},
    CapabilityBit{15, WA_TR(extcap_geospatial_location, "Geospatial Location")},
    CapabilityBit{16, WA_TR(extcap_tfs, "TFS")},
    CapabilityBit{17, WA_TR(extcap_wnm_sleep, "WNM Sleep Mode")},
    CapabilityBit{18, WA_TR(extcap_tim_broadcast, "TIM Broadcast")},
    CapabilityBit{19, WA_TR(extcap_bss_transition, "BSS Transition (802.11v)")},
    CapabilityBit{20, WA_TR(extcap_qos_traffic, "QoS Traffic Capability")},
    CapabilityBit{21, WA_TR(extcap_ac_station_count, "AC Station Count")},
    CapabilityBit{22, WA_TR(extcap_multiple_bssid, "Multiple BSSID")},
    CapabilityBit{23, WA_TR(extcap_timing_measurement, "Timing Measurement")},
    CapabilityBit{24, WA_TR(extcap_channel_usage, "Channel Usage")},
    CapabilityBit{25, WA_TR(extcap_ssid_list, "SSID List")},
    CapabilityBit{26, WA_TR(extcap_dms, "DMS")},
    CapabilityBit{27, WA_TR(extcap_utc_tsf_offset, "UTC TSF Offset")},
    CapabilityBit{28, WA_TR(extcap_tpu_buffer, "TPU Buffer STA Support")},
    CapabilityBit{29, WA_TR(extcap_tdls_psm, "TDLS Peer PSM Support")},
    CapabilityBit{30, WA_TR(extcap_tdls_channel_switching, "TDLS Channel Switching")},
    CapabilityBit{31, WA_TR(extcap_interworking, "Interworking")},
    CapabilityBit{32, WA_TR(extcap_qos_map, "QoS Map")},
    CapabilityBit{33, WA_TR(extcap_ebr, "EBR")},
    CapabilityBit{34, WA_TR(extcap_sspn, "SSPN Interface")},
    CapabilityBit{36, WA_TR(extcap_msgcf, "MSGCF Capability")},
    CapabilityBit{37, WA_TR(extcap_tdls, "TDLS Support")},
    CapabilityBit{38, WA_TR(extcap_tdls_prohibited, "TDLS Prohibited")},
    CapabilityBit{39, WA_TR(extcap_tdls_cs_prohibited, "TDLS Channel Switching Prohibited")},
    CapabilityBit{40, WA_TR(extcap_reject_unadmitted, "Reject Unadmitted Frame")},
    CapabilityBit{44, WA_TR(extcap_identifier_location, "Identifier Location")},
    CapabilityBit{45, WA_TR(extcap_uapsd_coexistence, "U-APSD Coexistence")},
    CapabilityBit{46, WA_TR(extcap_wnm_notification, "WNM Notification")},
    CapabilityBit{47, WA_TR(extcap_qab, "QAB Capability")},
    CapabilityBit{48, WA_TR(extcap_utf8_ssid, "UTF-8 SSID")},
    CapabilityBit{49, WA_TR(extcap_qmf_activated, "QMF Activated")},
    CapabilityBit{50, WA_TR(extcap_qmf_reconfiguration, "QMF Reconfiguration Activated")},
    CapabilityBit{51, WA_TR(extcap_robust_av_streaming, "Robust AV Streaming")},
    CapabilityBit{52, WA_TR(extcap_advanced_gcr, "Advanced GCR")},
    CapabilityBit{53, WA_TR(extcap_mesh_gcr, "Mesh GCR")},
    CapabilityBit{54, WA_TR(extcap_scs, "SCS")},
    CapabilityBit{55, WA_TR(extcap_qload_report, "QLoad Report")},
    CapabilityBit{56, WA_TR(extcap_alternate_edca, "Alternate EDCA")},
    CapabilityBit{57, WA_TR(extcap_unprotected_txop, "Unprotected TXOP Negotiation")},
    CapabilityBit{58, WA_TR(extcap_protected_txop, "Protected TXOP Negotiation")},
    CapabilityBit{60, WA_TR(extcap_protected_qload, "Protected QLoad Report")},
    CapabilityBit{61, WA_TR(extcap_tdls_wider_bandwidth, "TDLS Wider Bandwidth")},
    CapabilityBit{62, WA_TR(extcap_operating_mode_notification, "Operating Mode Notification")},
    CapabilityBit{65, WA_TR(extcap_channel_schedule, "Channel Schedule Management")},
    CapabilityBit{66, WA_TR(extcap_geodatabase, "Geodatabase Inband Enabling Signal")},
    CapabilityBit{67, WA_TR(extcap_network_channel_control, "Network Channel Control")},
    CapabilityBit{68, WA_TR(extcap_white_space_map, "White Space Map")},
    CapabilityBit{69, WA_TR(extcap_channel_availability_query, "Channel Availability Query")},
    CapabilityBit{70, WA_TR(extcap_ftm_responder, "Fine Timing Measurement Responder")},
    CapabilityBit{71, WA_TR(extcap_ftm_initiator, "Fine Timing Measurement Initiator")},
    CapabilityBit{72, WA_TR(extcap_fils, "FILS Capability")},
    CapabilityBit{77, WA_TR(extcap_twt_requester, "TWT Requester Support")},
    CapabilityBit{78, WA_TR(extcap_twt_responder, "TWT Responder Support")},
    CapabilityBit{79, WA_TR(extcap_obss_nb_ru, "OBSS Narrow Bandwidth RU in UL OFDMA Tolerance")},
    CapabilityBit{80, WA_TR(extcap_complete_nontx_profiles,
                            "Complete List of Nontransmitted BSSID Profiles")},
    CapabilityBit{81, WA_TR(extcap_sae_password_ids, "SAE Password Identifiers In Use")},
    CapabilityBit{
        82, WA_TR(extcap_sae_password_ids_exclusive, "SAE Password Identifiers Used Exclusively")},
    CapabilityBit{83, WA_TR(extcap_ema, "Enhanced Multi-BSSID Advertisement")},
    CapabilityBit{84, WA_TR(extcap_beacon_protection, "Beacon Protection Enabled")},
    CapabilityBit{85, WA_TR(extcap_mscs, "Mirrored SCS")},
    CapabilityBit{88, WA_TR(extcap_sae_pk_exclusive, "SAE-PK Passwords Used Exclusively")},
};

} // namespace

ElementValue decode_extended_capabilities(Decoder& d) {
    ExtendedCapabilities caps;
    const auto size = d.remaining();
    auto field = d.bits(WA_TR(extcap_field, "Extended Capabilities"), size);
    if (!field) {
        return {};
    }
    caps.bytes = field->data();
    const auto total_bits = static_cast<unsigned>(size * 8);

    std::size_t next_known = 0;
    for (unsigned bit = 0; bit < total_bits; ++bit) {
        if (bit == 41) {
            field->number(
                41, 3, WA_TR(extcap_service_interval_granularity, "Service Interval Granularity"));
            bit = 43;
            continue;
        }
        if (bit == 63) {
            field->number(63, 2, WA_TR(extcap_max_msdus_in_amsdu, "Max Number of MSDUs in A-MSDU"));
            bit = 64;
            continue;
        }
        while (next_known < known_bits.size() && known_bits[next_known].bit < bit) {
            ++next_known;
        }
        if (next_known < known_bits.size() && known_bits[next_known].bit == bit) {
            field->flag(bit, known_bits[next_known].label, true);
        } else if (field->test(bit)) {
            field->computed(bit, 1, WA_TR(extcap_unknown_bit, "Unknown Capability Bit"),
                            std::uint64_t{bit});
        }
    }
    d.add(field->take());
    return caps;
}

} // namespace wifi_analyze::ie
