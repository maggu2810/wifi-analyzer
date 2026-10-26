// SPDX-License-Identifier: MIT
#pragma once

// Typed values of decoded elements (layer 1, see docs/library.md). Only elements whose content
// is used by the summary or by frontends programmatically have a typed value; all elements
// have a decoded tree.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace wifi_analyze {

using Oui = std::array<std::uint8_t, 3>;
using MacAddress = std::array<std::uint8_t, 6>;

/// Cipher or AKM suite selector (OUI + suite type).
struct Suite {
    Oui oui{};
    std::uint8_t type{0};
    friend constexpr bool operator==(const Suite&, const Suite&) = default;
};

inline constexpr Oui oui_ieee80211{0x00, 0x0f, 0xac};
inline constexpr Oui oui_microsoft{0x00, 0x50, 0xf2};
inline constexpr Oui oui_wfa{0x50, 0x6f, 0x9a};

struct Ssid {
    std::vector<std::uint8_t> bytes;
    bool hidden{false}; ///< empty or all-zero SSID
};

struct Rate {
    std::uint8_t units_500kbps{0};
    bool basic{false};
};

/// Supported Rates (1) and Extended Supported Rates (50).
struct SupportedRates {
    std::vector<Rate> rates;
    std::vector<std::uint8_t> membership_selectors; ///< e.g. 127 HT PHY, 123 SAE-H2E only
};

struct DsParameterSet {
    std::uint8_t channel{0};
};

struct Country {
    std::string code;            ///< two letters as transmitted
    std::uint8_t environment{0}; ///< third octet: ' ', 'O', 'I', 'X' or operating class table
};

struct BssLoad {
    std::uint16_t station_count{0};
    std::uint8_t channel_utilization{0}; ///< x/255
    std::uint16_t available_admission_capacity{0};
};

struct PowerConstraint {
    std::uint8_t local_power_constraint_db{0};
};

struct HtCapabilities {
    std::uint16_t info{0};
    std::uint8_t ampdu_parameters{0};
    std::array<std::uint8_t, 16> mcs_set{};

    [[nodiscard]] bool supports_40mhz() const noexcept { return (info & 0x0002U) != 0; }
    [[nodiscard]] bool short_gi_20() const noexcept { return (info & 0x0020U) != 0; }
    [[nodiscard]] bool short_gi_40() const noexcept { return (info & 0x0040U) != 0; }
    /// Highest number of spatial streams with all of MCS 0..7 (8 MCS per stream) supported.
    [[nodiscard]] std::uint8_t rx_spatial_streams() const noexcept;
};

struct HtOperation {
    std::uint8_t primary_channel{0};
    std::uint8_t secondary_channel_offset{0}; ///< 0 none, 1 above, 3 below
    bool any_channel_width{false};            ///< STA Channel Width: 40 MHz allowed
    std::uint8_t ccfs2{0};                    ///< Channel Center Frequency Segment 2
};

struct Rsn {
    std::uint16_t version{0};
    std::optional<Suite> group_cipher;
    std::vector<Suite> pairwise_ciphers;
    std::vector<Suite> akms;
    std::optional<std::uint16_t> capabilities;
    std::size_t pmkid_count{0};
    std::optional<Suite> group_management_cipher;

    [[nodiscard]] bool mfp_required() const noexcept {
        return capabilities && (*capabilities & 0x0040U) != 0;
    }
    [[nodiscard]] bool mfp_capable() const noexcept {
        return capabilities && (*capabilities & 0x0080U) != 0;
    }
};

struct RsnExtension {
    std::vector<std::uint8_t> bytes;
    [[nodiscard]] bool bit(unsigned n) const noexcept {
        return n / 8 < bytes.size() && ((bytes[n / 8] >> (n % 8)) & 1U) != 0;
    }
    [[nodiscard]] bool sae_hash_to_element() const noexcept { return bit(5); }
    [[nodiscard]] bool sae_pk() const noexcept { return bit(6); }
};

struct MobilityDomain {
    std::uint16_t mdid{0};
    bool ft_over_ds{false};
    bool resource_request_protocol{false};
};

struct RmEnabledCapabilities {
    std::array<std::uint8_t, 5> bytes{};
    [[nodiscard]] bool bit(unsigned n) const noexcept {
        return n < 40 && ((bytes[n / 8] >> (n % 8)) & 1U) != 0;
    }
    [[nodiscard]] bool neighbor_report() const noexcept { return bit(1); }
};

struct ExtendedCapabilities {
    std::vector<std::uint8_t> bytes;
    [[nodiscard]] bool bit(unsigned n) const noexcept {
        return n / 8 < bytes.size() && ((bytes[n / 8] >> (n % 8)) & 1U) != 0;
    }
    [[nodiscard]] bool bss_transition() const noexcept { return bit(19); }
    [[nodiscard]] bool interworking() const noexcept { return bit(31); }
    [[nodiscard]] bool twt_responder() const noexcept { return bit(78); }
};

struct VhtCapabilities {
    std::uint32_t info{0};
    std::uint16_t rx_mcs_map{0xffff};
    std::uint16_t tx_mcs_map{0xffff};

    [[nodiscard]] std::uint8_t supported_channel_width_set() const noexcept {
        return static_cast<std::uint8_t>((info >> 2U) & 0x3U);
    }
    [[nodiscard]] bool short_gi_80() const noexcept { return (info & (1U << 5U)) != 0; }
    [[nodiscard]] bool short_gi_160() const noexcept { return (info & (1U << 6U)) != 0; }
};

struct VhtOperation {
    std::uint8_t channel_width{0}; ///< 0 = 20/40, 1 = 80/160/80+80, 2/3 deprecated 160/80+80
    std::uint8_t ccfs0{0};
    std::uint8_t ccfs1{0};
    std::uint16_t basic_mcs_map{0};
};

struct Interworking {
    std::uint8_t access_network_type{0};
    bool internet{false};
    bool asra{false};
    bool esr{false};
    bool uesa{false};
    std::optional<std::uint8_t> venue_group;
    std::optional<std::uint8_t> venue_type;
    std::optional<MacAddress> hessid;
};

/// HE Capabilities (extension 35).
struct HeCapabilities {
    std::array<std::uint8_t, 6> mac{};
    std::array<std::uint8_t, 11> phy{};
    std::uint16_t rx_mcs_80{0xffff};
    std::uint16_t tx_mcs_80{0xffff};
    std::optional<std::uint16_t> rx_mcs_160;
    std::optional<std::uint16_t> tx_mcs_160;
    std::optional<std::uint16_t> rx_mcs_80p80;
    std::optional<std::uint16_t> tx_mcs_80p80;

    [[nodiscard]] bool phy_bit(unsigned n) const noexcept {
        return n < 88 && ((phy[n / 8] >> (n % 8)) & 1U) != 0;
    }
    [[nodiscard]] bool mac_bit(unsigned n) const noexcept {
        return n < 48 && ((mac[n / 8] >> (n % 8)) & 1U) != 0;
    }
    [[nodiscard]] bool supports_160mhz() const noexcept { return phy_bit(3); }
    [[nodiscard]] bool supports_80p80mhz() const noexcept { return phy_bit(4); }
    /// Channel Width Set B0..B3 all zero: 20 MHz-only device.
    [[nodiscard]] bool twenty_mhz_only() const noexcept { return (phy[0] & 0x1eU) == 0; }
};

struct He6GhzOperation {
    std::uint8_t primary_channel{0};
    std::uint8_t channel_width{0}; ///< 0 = 20, 1 = 40, 2 = 80, 3 = 160/80+80
    bool duplicate_beacon{false};
    std::uint8_t regulatory_info{0};
    std::uint8_t ccfs0{0};
    std::uint8_t ccfs1{0};
    std::uint8_t minimum_rate{0};
};

/// HE Operation (extension 36).
struct HeOperation {
    std::uint32_t parameters{0}; ///< 24 bits
    std::uint8_t bss_color{0};
    bool partial_bss_color{false};
    bool bss_color_disabled{false};
    std::uint16_t basic_mcs_map{0};
    std::optional<VhtOperation> vht_operation; ///< embedded VHT Operation Information
    std::optional<std::uint8_t> max_cohosted_bssid_indicator;
    std::optional<He6GhzOperation> six_ghz;

    [[nodiscard]] bool twt_required() const noexcept { return (parameters & (1U << 3U)) != 0; }
    [[nodiscard]] bool er_su_disable() const noexcept { return (parameters & (1U << 16U)) != 0; }
};

struct EhtMcsMap {
    /// Max NSS per MCS group: [0] = MCS 0-9 (or 0-7 for 20 MHz-only), [1] = 10-11, [2] = 12-13.
    std::array<std::uint8_t, 3> rx_max_nss{};
    std::array<std::uint8_t, 3> tx_max_nss{};
};

/// EHT Capabilities (extension 108).
struct EhtCapabilities {
    std::uint16_t mac{0};
    std::array<std::uint8_t, 9> phy{};
    std::optional<EhtMcsMap> mcs_80; ///< BW <= 80 MHz (or 20 MHz-only map)
    std::optional<EhtMcsMap> mcs_160;
    std::optional<EhtMcsMap> mcs_320;

    [[nodiscard]] bool phy_bit(unsigned n) const noexcept {
        return n < 72 && ((phy[n / 8] >> (n % 8)) & 1U) != 0;
    }
    [[nodiscard]] bool supports_320mhz() const noexcept { return phy_bit(1); }
};

struct EhtOperationInfo {
    std::uint8_t channel_width{0}; ///< 0 = 20, 1 = 40, 2 = 80, 3 = 160, 4 = 320
    std::uint8_t ccfs0{0};
    std::uint8_t ccfs1{0};
    std::optional<std::uint16_t> disabled_subchannels;
};

/// EHT Operation (extension 106).
struct EhtOperation {
    std::uint8_t parameters{0};
    std::array<std::uint8_t, 4> basic_mcs{};
    std::optional<EhtOperationInfo> info;
};

struct MultiLinkPerSta {
    std::uint8_t link_id{0};
    bool complete_profile{false};
    std::optional<MacAddress> sta_mac;
};

/// Multi-Link (extension 107).
struct MultiLink {
    std::uint8_t type{0}; ///< 0 = Basic
    std::optional<MacAddress> mld_mac;
    std::optional<std::uint8_t> link_id;
    std::optional<std::uint8_t> max_simultaneous_links; ///< as transmitted (value + 1 links)
    std::optional<std::uint8_t> ap_mld_id;
    std::vector<MultiLinkPerSta> per_sta;
};

struct RnrTbttInfo {
    std::optional<MacAddress> bssid;
    std::optional<std::uint32_t> short_ssid;
    std::optional<std::uint8_t> bss_parameters;
    std::optional<std::uint8_t> mld_ap_id;
    std::optional<std::uint8_t> mld_link_id;

    [[nodiscard]] bool same_ssid() const noexcept {
        return bss_parameters && (*bss_parameters & 0x02U) != 0;
    }
    [[nodiscard]] bool co_located() const noexcept {
        return bss_parameters && (*bss_parameters & 0x40U) != 0;
    }
};

struct RnrNeighbor {
    std::uint8_t operating_class{0};
    std::uint8_t channel{0};
    std::vector<RnrTbttInfo> tbtt;
};

/// Reduced Neighbor Report (201).
struct ReducedNeighborReport {
    std::vector<RnrNeighbor> neighbors;
};

/// Multiple BSSID (71).
struct MultipleBssid {
    std::uint8_t max_bssid_indicator{0};
    std::size_t nontransmitted_profiles{0};
};

/// Legacy WPA vendor element (00:50:F2 type 1).
struct Wpa {
    std::uint16_t version{0};
    std::optional<Suite> group_cipher;
    std::vector<Suite> pairwise_ciphers;
    std::vector<Suite> akms;
};

struct WmmAc {
    std::uint8_t aci{0}; ///< 0 BE, 1 BK, 2 VI, 3 VO
    std::uint8_t aifsn{0};
    bool acm{false};
    std::uint8_t ecw_min{0};
    std::uint8_t ecw_max{0};
    std::uint16_t txop_limit{0}; ///< units of 32 µs
};

/// WMM Information / Parameter element (00:50:F2 type 2).
struct Wmm {
    std::uint8_t subtype{0};
    std::uint8_t qos_info{0};
    std::vector<WmmAc> access_categories;
    [[nodiscard]] bool uapsd() const noexcept { return (qos_info & 0x80U) != 0; }
};

/// Wi-Fi Protected Setup (00:50:F2 type 4).
struct Wps {
    std::optional<std::uint8_t> version;
    std::optional<std::uint8_t> version2;
    std::optional<std::uint8_t> state; ///< 1 not configured, 2 configured
    bool ap_setup_locked{false};
    bool selected_registrar{false};
    std::optional<std::uint16_t> config_methods;
    std::optional<std::uint16_t> device_password_id;
    std::string manufacturer;
    std::string model_name;
    std::string model_number;
    std::string serial_number;
    std::string device_name;
    std::optional<std::uint16_t> primary_device_category;
};

/// OWE Transition Mode (50:6F:9A type 0x1C).
struct OweTransition {
    MacAddress bssid{};
    std::vector<std::uint8_t> ssid;
    std::optional<std::uint8_t> operating_class;
    std::optional<std::uint8_t> channel;
};

/// Hotspot 2.0 Indication (50:6F:9A type 0x10).
struct Hs20Indication {
    std::uint8_t release{0}; ///< 0 = Release 1
    bool dgaf_disabled{false};
};

using ElementValue =
    std::variant<std::monostate, Ssid, SupportedRates, DsParameterSet, Country, BssLoad,
                 PowerConstraint, HtCapabilities, HtOperation, Rsn, RsnExtension, MobilityDomain,
                 RmEnabledCapabilities, ExtendedCapabilities, VhtCapabilities, VhtOperation,
                 Interworking, HeCapabilities, HeOperation, EhtCapabilities, EhtOperation,
                 MultiLink, ReducedNeighborReport, MultipleBssid, Wpa, Wmm, Wps, OweTransition,
                 Hs20Indication>;

} // namespace wifi_analyze
