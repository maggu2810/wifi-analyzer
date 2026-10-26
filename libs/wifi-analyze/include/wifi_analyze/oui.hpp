// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <wifi_analyze/diagnostic.hpp>
#include <wifi_analyze/elements.hpp>

namespace wifi_analyze {

/// Full vendor database parsed from the IEEE MA-L registry CSV (oui.csv). The library never
/// downloads or reads files; frontends obtain the text and hand it in.
class OuiDatabase {
public:
    OuiDatabase() = default;

    /// Parses IEEE "Registry,Assignment,Organization Name,Organization Address" CSV text.
    /// Rows that are not 24-bit assignments are skipped.
    [[nodiscard]] static std::expected<OuiDatabase, Diagnostic>
    parse_ieee_csv(std::string_view csv);

    [[nodiscard]] std::optional<std::string_view> find(const Oui& oui) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

private:
    std::vector<std::pair<std::uint32_t, std::string>> entries_; // sorted by OUI
};

/// Vendor from the small built-in table.
[[nodiscard]] std::optional<std::string_view> builtin_oui_name(const Oui& oui) noexcept;

/// Lookup in `database` (if given), then in the built-in table.
[[nodiscard]] std::optional<std::string_view> oui_name(const Oui& oui,
                                                       const OuiDatabase* database) noexcept;

/// OUI of a MAC address; nullopt for locally administered or group addresses.
[[nodiscard]] std::optional<Oui> oui_of_mac(const MacAddress& mac) noexcept;

} // namespace wifi_analyze
