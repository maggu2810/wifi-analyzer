// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <wifi_analyze/elements.hpp>

namespace wifi_analyze {

/// Capture exchange format (docs/data-formats.md §3). Reading/writing the JSON is done by
/// frontends; the library provides the identifiers and IE-level anonymization.
inline constexpr std::string_view capture_format = "wifi-analyze.capture";
inline constexpr int capture_format_version = 1;

struct AnonymizeOptions {
    /// Per-export salt; the same salt maps the same input to the same pseudonym.
    std::uint64_t salt{0};
    /// Keep the vendor OUI of MAC addresses (first three octets) so vendors stay visible.
    bool keep_oui{true};
};

/// Rewrites identifying content of an IE stream: SSIDs (also in OWE transition, Multiple BSSID
/// profiles, Mesh ID), WPS device name / serial number / UUID, BSSIDs and MLD addresses (RNR,
/// OWE transition, Multi-Link, HESSID). Manufacturer and model are kept. The element structure
/// is preserved; malformed elements are kept unchanged.
[[nodiscard]] std::vector<std::uint8_t> anonymize_ies(std::span<const std::uint8_t> ies,
                                                      const AnonymizeOptions& options);

[[nodiscard]] MacAddress anonymize_mac(const MacAddress& mac, const AnonymizeOptions& options);

/// Pseudonym for an SSID ("ssid-1a2b3c4d"); empty and all-zero (hidden) SSIDs are kept as is.
[[nodiscard]] std::vector<std::uint8_t> anonymize_ssid(std::span<const std::uint8_t> ssid,
                                                       const AnonymizeOptions& options);

} // namespace wifi_analyze
