// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <wifi_analyze/elements.hpp>

namespace wifi_analyze_cli {

enum class InputFormat {
    auto_detect,
    hex,
    wpa_bss, ///< one or more `wpa_cli BSS` blocks (key=value lines)
    capture, ///< wifi-analyze.capture JSON
};

/// One observed BSS from any input format. Only `ies` is mandatory.
struct InputBss {
    std::optional<wifi_analyze::MacAddress> bssid;
    std::optional<std::string> ssid; ///< as reported by the source (wpa_cli: escaped text)
    std::optional<std::uint32_t> frequency_mhz;
    std::optional<int> signal_dbm;
    std::optional<std::uint64_t> age_ms;
    std::optional<std::uint16_t> capabilities; ///< Capability Information field
    std::optional<bool> privacy;
    std::string flags; ///< wpa_cli flags, e.g. "[WPA2-PSK-CCMP][ESS]"
    std::vector<std::uint8_t> ies;
    std::optional<std::vector<std::uint8_t>> beacon_ies;
    std::string timestamp; ///< capture: scan timestamp
};

struct InputError {
    std::string message;
};

[[nodiscard]] std::optional<InputFormat> parse_input_format(std::string_view name);
[[nodiscard]] InputFormat detect_format(std::string_view text);

/// Parses text in the given (or detected) format.
[[nodiscard]] std::expected<std::vector<InputBss>, InputError> parse_input(std::string_view text,
                                                                           InputFormat format);

[[nodiscard]] std::optional<wifi_analyze::MacAddress> parse_mac(std::string_view text);
[[nodiscard]] std::string format_mac(const wifi_analyze::MacAddress& mac);

} // namespace wifi_analyze_cli
