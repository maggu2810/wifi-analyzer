// SPDX-License-Identifier: MIT
#include "input.hpp"

#include <algorithm>
#include <charconv>
#include <format>
#include <nlohmann/json.hpp>

#include <wifi_analyze/capture.hpp>
#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/i18n.hpp>

namespace wifi_analyze_cli {
namespace {

std::string_view trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

template <class T>
std::optional<T> to_number(std::string_view s, int base = 10) {
    s = trim(s);
    if (base == 16 && (s.starts_with("0x") || s.starts_with("0X"))) {
        s.remove_prefix(2);
    }
    T value{};
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value, base);
    if (ec != std::errc{} || ptr != s.data() + s.size()) {
        return std::nullopt;
    }
    return value;
}

std::expected<std::vector<std::uint8_t>, InputError> hex_field(std::string_view value,
                                                               std::string_view key) {
    auto bytes = wifi_analyze::parse_hex(value);
    if (!bytes) {
        return std::unexpected(InputError{std::format(
            "{}: {}", key,
            wifi_analyze::Localizer{}.format(bytes.error().message, bytes.error().args))});
    }
    return std::move(*bytes);
}

std::expected<std::vector<InputBss>, InputError> parse_wpa_bss(std::string_view text) {
    std::vector<InputBss> result;
    InputBss current;
    bool has_content = false;
    bool has_ies = false;
    const auto flush = [&] -> std::expected<void, InputError> {
        if (has_content) {
            if (!has_ies) {
                return std::unexpected(InputError{"wpa_cli BSS block without 'ie=' line"});
            }
            result.push_back(std::move(current));
        }
        current = InputBss{};
        has_content = false;
        has_ies = false;
        return {};
    };

    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto end = std::min(text.find('\n', pos), text.size());
        const auto line = trim(text.substr(pos, end - pos));
        pos = end + 1;
        const auto eq = line.find('=');
        if (eq == std::string_view::npos || eq == 0) {
            continue; // prompts, "Selected interface ..." and other noise
        }
        const auto key = line.substr(0, eq);
        const auto value = line.substr(eq + 1);
        if ((key == "id" || key == "bssid") && (current.bssid || (key == "id" && has_content))) {
            if (auto r = flush(); !r) {
                return std::unexpected(r.error());
            }
        }
        has_content = true;
        if (key == "bssid") {
            current.bssid = parse_mac(value);
        } else if (key == "freq") {
            current.frequency_mhz = to_number<std::uint32_t>(value);
        } else if (key == "level") {
            current.signal_dbm = to_number<int>(value);
        } else if (key == "age") {
            if (const auto s = to_number<std::uint64_t>(value)) {
                current.age_ms = *s * 1000;
            }
        } else if (key == "capabilities") {
            current.capabilities = to_number<std::uint16_t>(value, 16);
            if (current.capabilities) {
                current.privacy = (*current.capabilities & 0x0010U) != 0;
            }
        } else if (key == "flags") {
            current.flags = std::string{value};
        } else if (key == "ssid") {
            current.ssid = std::string{value};
        } else if (key == "ie") {
            auto bytes = hex_field(value, "ie");
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            current.ies = std::move(*bytes);
            has_ies = true;
        } else if (key == "beacon_ie") {
            auto bytes = hex_field(value, "beacon_ie");
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            current.beacon_ies = std::move(*bytes);
        }
    }
    if (auto r = flush(); !r) {
        return std::unexpected(r.error());
    }
    if (result.empty()) {
        return std::unexpected(InputError{"no BSS found in wpa_cli output"});
    }
    return result;
}

std::expected<std::vector<InputBss>, InputError> parse_capture(std::string_view text) {
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(text);
    } catch (const nlohmann::json::exception& e) {
        return std::unexpected(InputError{std::format("invalid JSON: {}", e.what())});
    }
    if (!doc.is_object() || doc.value("format", "") != wifi_analyze::capture_format) {
        return std::unexpected(InputError{"not a wifi-analyze.capture document"});
    }
    if (doc.value("format_version", 0) > wifi_analyze::capture_format_version) {
        return std::unexpected(InputError{"capture format version is newer than supported"});
    }
    std::vector<InputBss> result;
    try {
        for (const auto& scan : doc.value("scans", nlohmann::json::array())) {
            const auto timestamp = scan.value("timestamp", std::string{});
            for (const auto& b : scan.value("bss", nlohmann::json::array())) {
                InputBss bss;
                bss.timestamp = timestamp;
                if (b.contains("bssid") && b["bssid"].is_string()) {
                    bss.bssid = parse_mac(b["bssid"].get<std::string>());
                }
                if (b.contains("ssid") && b["ssid"].is_string()) {
                    bss.ssid = b["ssid"].get<std::string>();
                }
                if (b.contains("freq_mhz") && b["freq_mhz"].is_number_unsigned()) {
                    bss.frequency_mhz = b["freq_mhz"].get<std::uint32_t>();
                }
                if (b.contains("signal_dbm") && b["signal_dbm"].is_number_integer()) {
                    bss.signal_dbm = b["signal_dbm"].get<int>();
                }
                if (b.contains("age_ms") && b["age_ms"].is_number_unsigned()) {
                    bss.age_ms = b["age_ms"].get<std::uint64_t>();
                }
                if (b.contains("capabilities") && b["capabilities"].is_number_unsigned()) {
                    bss.capabilities = b["capabilities"].get<std::uint16_t>();
                    bss.privacy = (*bss.capabilities & 0x0010U) != 0;
                }
                if (b.contains("platform") && b["platform"].is_object() &&
                    b["platform"].contains("capabilities") &&
                    b["platform"]["capabilities"].is_string()) {
                    bss.flags = b["platform"]["capabilities"].get<std::string>();
                }
                auto ies = hex_field(b.value("ies", std::string{}), "ies");
                if (!ies) {
                    return std::unexpected(ies.error());
                }
                bss.ies = std::move(*ies);
                if (b.contains("beacon_ies") && b["beacon_ies"].is_string()) {
                    auto beacon = hex_field(b["beacon_ies"].get<std::string>(), "beacon_ies");
                    if (!beacon) {
                        return std::unexpected(beacon.error());
                    }
                    bss.beacon_ies = std::move(*beacon);
                }
                if (!bss.privacy && !bss.flags.empty()) {
                    // Android capabilities string, e.g. "[WPA2-PSK-CCMP][ESS]" or "[WEP]"
                    bss.privacy = bss.flags.contains("WEP") || bss.flags.contains("WPA") ||
                                  bss.flags.contains("RSN") || bss.flags.contains("SAE") ||
                                  bss.flags.contains("OWE");
                }
                result.push_back(std::move(bss));
            }
        }
    } catch (const nlohmann::json::exception& e) {
        return std::unexpected(InputError{std::format("invalid capture: {}", e.what())});
    }
    if (result.empty()) {
        return std::unexpected(InputError{"capture contains no BSS"});
    }
    return result;
}

} // namespace

std::optional<InputFormat> parse_input_format(std::string_view name) {
    if (name == "auto") {
        return InputFormat::auto_detect;
    }
    if (name == "hex") {
        return InputFormat::hex;
    }
    if (name == "wpa-bss") {
        return InputFormat::wpa_bss;
    }
    if (name == "capture") {
        return InputFormat::capture;
    }
    return std::nullopt;
}

InputFormat detect_format(std::string_view text) {
    const auto t = trim(text);
    if (t.starts_with('{')) {
        return InputFormat::capture;
    }
    if (t.contains('=')) {
        return InputFormat::wpa_bss;
    }
    return InputFormat::hex;
}

std::expected<std::vector<InputBss>, InputError> parse_input(std::string_view text,
                                                             InputFormat format) {
    if (format == InputFormat::auto_detect) {
        format = detect_format(text);
    }
    switch (format) {
    case InputFormat::capture:
        return parse_capture(text);
    case InputFormat::wpa_bss:
        return parse_wpa_bss(text);
    case InputFormat::hex:
    case InputFormat::auto_detect: {
        auto bytes = hex_field(text, "hex");
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        InputBss bss;
        bss.ies = std::move(*bytes);
        return std::vector<InputBss>{std::move(bss)};
    }
    }
    return std::unexpected(InputError{"unknown input format"});
}

std::optional<wifi_analyze::MacAddress> parse_mac(std::string_view text) {
    const auto bytes = wifi_analyze::parse_hex(trim(text));
    if (!bytes || bytes->size() != 6) {
        return std::nullopt;
    }
    wifi_analyze::MacAddress mac{};
    std::ranges::copy(*bytes, mac.begin());
    return mac;
}

std::string format_mac(const wifi_analyze::MacAddress& mac) {
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3],
                       mac[4], mac[5]);
}

} // namespace wifi_analyze_cli
