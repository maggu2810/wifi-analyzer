// SPDX-License-Identifier: MIT
#pragma once

#include <expected>
#include <filesystem>
#include <optional>
#include <ostream>
#include <string>

#include <wifi_analyze/oui.hpp>

namespace wifi_analyze_cli {

inline constexpr std::string_view default_oui_url = "https://standards-oui.ieee.org/oui/oui.csv";

/// $XDG_CACHE_HOME/wifi-analyze/oui.csv (fallback ~/.cache/...).
[[nodiscard]] std::filesystem::path oui_cache_path();

/// Loads the cached database if present (nullopt if absent or invalid).
[[nodiscard]] std::optional<wifi_analyze::OuiDatabase> load_oui_cache();

[[nodiscard]] bool oui_download_supported() noexcept;

/// Validates CSV text and stores it atomically in the cache. Returns the number of entries.
[[nodiscard]] std::expected<std::size_t, std::string> store_oui_csv(const std::string& csv);

[[nodiscard]] std::expected<std::string, std::string> download(const std::string& url);

} // namespace wifi_analyze_cli
