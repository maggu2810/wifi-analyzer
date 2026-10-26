// SPDX-License-Identifier: MIT
#include <algorithm>
#include <array>
#include <string>

#include <wifi_analyze/oui.hpp>

#include "core/decoder.hpp"
#include "core/tr.hpp"

namespace wifi_analyze {
namespace {

struct BuiltinOui {
    std::uint32_t oui;
    std::string_view name;
};

#include "oui_builtin.inc"

/// Splits one CSV record (RFC 4180 quoting) starting at `pos`; advances `pos` past it.
std::vector<std::string> next_record(std::string_view csv, std::size_t& pos) {
    std::vector<std::string> fields(1);
    bool quoted = false;
    while (pos < csv.size()) {
        const char c = csv[pos++];
        if (quoted) {
            if (c == '"') {
                if (pos < csv.size() && csv[pos] == '"') {
                    fields.back().push_back('"');
                    ++pos;
                } else {
                    quoted = false;
                }
            } else {
                fields.back().push_back(c);
            }
        } else if (c == '"') {
            quoted = true;
        } else if (c == ',') {
            fields.emplace_back();
        } else if (c == '\n') {
            break;
        } else if (c != '\r') {
            fields.back().push_back(c);
        }
    }
    return fields;
}

std::optional<std::uint32_t> parse_assignment(std::string_view s) {
    if (s.size() != 6) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (const char c : s) {
        std::uint32_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::uint32_t>(c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::uint32_t>(c - 'a' + 10);
        } else {
            return std::nullopt;
        }
        value = (value << 4U) | digit;
    }
    return value;
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = s.find_last_not_of(" \t");
    return s.substr(first, last - first + 1);
}

} // namespace

std::expected<OuiDatabase, Diagnostic> OuiDatabase::parse_ieee_csv(std::string_view csv) {
    OuiDatabase db;
    std::size_t pos = 0;
    while (pos < csv.size()) {
        auto fields = next_record(csv, pos);
        if (fields.size() < 3) {
            continue;
        }
        const auto oui = parse_assignment(trim(fields[1]));
        auto name = trim(fields[2]);
        if (!oui || name.empty()) {
            continue; // header line or other registries
        }
        db.entries_.emplace_back(*oui, std::move(name));
    }
    if (db.entries_.empty()) {
        return std::unexpected(Diagnostic{
            .severity = Severity::error,
            .message = WA_TR(oui_csv_invalid, "The OUI file contains no IEEE MA-L assignments"),
            .args = {},
            .bytes = std::nullopt,
        });
    }
    std::ranges::stable_sort(db.entries_, {}, &std::pair<std::uint32_t, std::string>::first);
    // Keep the first entry for duplicate assignments.
    const auto dup =
        std::ranges::unique(db.entries_, {}, &std::pair<std::uint32_t, std::string>::first);
    db.entries_.erase(dup.begin(), dup.end());
    return db;
}

std::optional<std::string_view> OuiDatabase::find(const Oui& oui) const noexcept {
    const auto key = core::oui_value(oui);
    const auto it =
        std::ranges::lower_bound(entries_, key, {}, &std::pair<std::uint32_t, std::string>::first);
    if (it == entries_.end() || it->first != key) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<std::string_view> builtin_oui_name(const Oui& oui) noexcept {
    const auto key = core::oui_value(oui);
    const auto* const it = std::ranges::lower_bound(builtin_ouis, key, {}, &BuiltinOui::oui);
    if (it == builtin_ouis.end() || it->oui != key) {
        return std::nullopt;
    }
    return it->name;
}

std::optional<std::string_view> oui_name(const Oui& oui, const OuiDatabase* database) noexcept {
    if (database != nullptr) {
        if (const auto name = database->find(oui)) {
            return name;
        }
    }
    return builtin_oui_name(oui);
}

std::optional<Oui> oui_of_mac(const MacAddress& mac) noexcept {
    if ((mac[0] & 0x03U) != 0) {
        return std::nullopt; // group or locally administered (e.g. randomized) address
    }
    return Oui{mac[0], mac[1], mac[2]};
}

} // namespace wifi_analyze
