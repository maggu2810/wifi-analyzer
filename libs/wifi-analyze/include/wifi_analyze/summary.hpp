// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <wifi_analyze/channel.hpp>
#include <wifi_analyze/elements.hpp>
#include <wifi_analyze/ie.hpp>
#include <wifi_analyze/tree.hpp>

namespace wifi_analyze {

enum class SecurityType : std::uint8_t {
    unknown,     ///< RSN/WPA present but not classifiable (malformed, only unknown AKMs)
    open,        ///< privacy known to be off
    open_or_wep, ///< no RSN/WPA and privacy bit unknown
    wep,
    enhanced_open,            ///< OWE
    enhanced_open_transition, ///< open BSS advertising an OWE transition BSS
    wpa_personal,
    wpa_enterprise,
    wpa_wpa2_personal,
    wpa_wpa2_enterprise,
    wpa2_personal,
    wpa2_wpa3_personal,
    wpa3_personal,
    wpa2_enterprise,
    wpa2_wpa3_enterprise,
    wpa3_enterprise,
    wpa3_enterprise_192,
    other, ///< e.g. only FILS, DPP or OSEN
};

enum class Pmf : std::uint8_t {
    unknown,
    disabled,
    capable,
    required,
};

struct SecuritySummary {
    SecurityType type{SecurityType::unknown};
    Pmf pmf{Pmf::unknown};
    bool wpa1{false};
    bool rsn{false};
    std::optional<Suite> group_cipher;
    std::vector<Suite> pairwise_ciphers;
    std::vector<Suite> akms;
    std::optional<Suite> group_management_cipher;
    bool sae_hash_to_element{false};
    bool sae_pk{false};
    bool weak{false}; ///< WEP or TKIP in use, open, or legacy WPA
};

enum class PhyStandard : std::uint8_t { b, a, g, n, ac, ax, be };

struct PhySummary {
    /// Wi-Fi generation: 0 = legacy (a/b/g), 4 = 802.11n, 5 = ac, 6 = ax, 7 = be.
    std::uint8_t generation{0};
    std::vector<PhyStandard> standards;
    Band band{Band::unknown};
    std::optional<std::uint16_t> primary_channel;
    std::optional<std::uint32_t> primary_frequency_mhz;
    std::uint16_t channel_width_mhz{20};
    bool eighty_plus_eighty{false};
    /// Center frequencies of the occupied channel (one, or two for 80+80).
    std::vector<std::uint32_t> center_frequencies_mhz;
    /// Disabled 20 MHz subchannels (EHT puncturing), bit 0 = lowest.
    std::optional<std::uint16_t> punctured_subchannels;
    std::uint8_t max_spatial_streams{0};
    /// Estimated maximum PHY data rate of the AP (Mbit/s) at the operating width.
    std::optional<double> max_rate_mbps;
    std::optional<double> max_legacy_rate_mbps;
};

struct Roaming {
    bool k{false}; ///< 802.11k neighbor reports
    bool v{false}; ///< 802.11v BSS transition management
    bool r{false}; ///< 802.11r fast BSS transition
    bool ft_over_ds{false};
};

struct DeviceInfo {
    std::string manufacturer;
    std::string model_name;
    std::string model_number;
    std::string device_name;
    std::string serial_number;
    [[nodiscard]] bool empty() const noexcept {
        return manufacturer.empty() && model_name.empty() && model_number.empty() &&
               device_name.empty() && serial_number.empty();
    }
};

struct VendorTag {
    Oui oui{};
    std::string name; ///< empty if unknown
};

struct MloSummary {
    std::optional<MacAddress> mld_mac;
    std::optional<std::uint8_t> link_id;
    std::optional<std::uint8_t> max_simultaneous_links;
    std::size_t reported_links{0};
};

struct NeighborSummary {
    std::uint8_t operating_class{0};
    std::uint8_t channel{0};
    Band band{Band::unknown};
    std::optional<MacAddress> bssid;
    bool same_ssid{false};
    bool co_located{false};
};

struct BssSummary {
    std::string ssid; ///< display form (escaped if not UTF-8)
    std::vector<std::uint8_t> ssid_raw;
    bool ssid_present{false};
    bool hidden{false};

    SecuritySummary security;
    PhySummary phy;

    std::optional<BssLoad> bss_load;
    std::string country;
    std::optional<std::uint8_t> country_environment;
    Roaming roaming;
    bool wmm{false};
    bool uapsd{false};
    std::optional<std::uint8_t> bss_color;
    bool twt_responder{false};
    std::optional<MloSummary> mlo;
    std::vector<NeighborSummary> neighbors;
    std::size_t nontransmitted_bssids{0};
    DeviceInfo device;
    std::optional<std::uint8_t> access_network_type;
    std::optional<bool> internet;
    std::optional<std::uint8_t> hotspot20_release;
    std::vector<VendorTag> vendors;
    std::size_t element_count{0};
    std::size_t problem_count{0}; ///< elements with status malformed/truncated + stream issues
};

/// Derives the per-BSS summary from decoded elements.
[[nodiscard]] BssSummary summarize(const DecodedIes& ies, const DecodeContext& context = {});

/// Presentation-neutral overview of a summary (rendered like element trees).
[[nodiscard]] TreeNode describe(const BssSummary& summary);

[[nodiscard]] Text security_type_name(SecurityType type) noexcept;
[[nodiscard]] Text pmf_name(Pmf pmf) noexcept;
[[nodiscard]] std::string_view phy_standard_name(PhyStandard standard) noexcept;
/// "Wi-Fi 6E" style name, "Legacy" for generation 0.
[[nodiscard]] std::string generation_name(const PhySummary& phy);
/// Stable machine key of a security type, e.g. "wpa2_wpa3_personal".
[[nodiscard]] std::string_view security_type_key(SecurityType type) noexcept;

/// Theoretical PHY rate (Mbit/s) for one configuration; nullopt if invalid.
/// phy: 4 = HT, 5 = VHT, 6 = HE, 7 = EHT. Short GI applies to HT/VHT only.
[[nodiscard]] std::optional<double> phy_rate_mbps(int phy, unsigned width_mhz, unsigned mcs,
                                                  unsigned nss, bool short_gi) noexcept;

} // namespace wifi_analyze
