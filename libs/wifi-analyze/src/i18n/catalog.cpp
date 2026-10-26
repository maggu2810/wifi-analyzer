// SPDX-License-Identifier: MIT
#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>

#include <wifi_analyze/i18n.hpp>

namespace wifi_analyze {
namespace {

struct LocaleCatalog {
    std::string_view locale;
    const std::array<std::string_view, message_count>* texts;
};

#include "i18n_catalog.inc"

static_assert(!catalogs.empty() && catalogs[0].locale == "en", "English catalog must be first");

constexpr auto locale_names = [] {
    std::array<std::string_view, catalogs.size()> names{};
    for (std::size_t i = 0; i < catalogs.size(); ++i) {
        names[i] = catalogs[i].locale;
    }
    return names;
}();

constexpr std::size_t index_of(MessageId id) noexcept {
    return static_cast<std::size_t>(id);
}

std::optional<std::size_t> find_catalog(std::string_view name) noexcept {
    const auto* const it = std::ranges::find(catalogs, name, &LocaleCatalog::locale);
    if (it == catalogs.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(it - catalogs.begin());
}

constexpr char to_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr char to_upper(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

} // namespace

Localizer::Localizer() noexcept = default;

std::string_view Localizer::locale() const noexcept {
    return catalogs[catalog_].locale;
}

std::string_view Localizer::text(MessageId id) const noexcept {
    const auto index = index_of(id);
    if (index >= message_count) {
        return {};
    }
    const auto translated = (*catalogs[catalog_].texts)[index];
    return translated.empty() ? catalog_en[index] : translated;
}

std::string Localizer::format(MessageId id, std::span<const std::string> args) const {
    return format_message(text(id), args);
}

Localizer localizer(std::string_view locale) noexcept {
    // Strip encoding and modifier: "de_DE.UTF-8@euro" -> "de_DE".
    locale = locale.substr(0, locale.find_first_of(".@"));

    // Normalize to "ll" / "ll_RR".
    std::array<char, 16> buffer{};
    std::size_t len = 0;
    bool region = false;
    for (const char c : locale) {
        if (len == buffer.size()) {
            return Localizer{};
        }
        if (c == '-' || c == '_') {
            region = true;
            buffer[len++] = '_';
        } else {
            buffer[len++] = region ? to_upper(c) : to_lower(c);
        }
    }
    const std::string_view normalized{buffer.data(), len};

    if (const auto exact = find_catalog(normalized)) {
        return Localizer{*exact};
    }
    if (const auto language = find_catalog(normalized.substr(0, normalized.find('_')))) {
        return Localizer{*language};
    }
    return Localizer{};
}

std::span<const std::string_view> available_locales() noexcept {
    return locale_names;
}

std::string_view message_key(MessageId id) noexcept {
    const auto index = index_of(id);
    return index < message_count ? message_keys[index] : std::string_view{};
}

std::optional<MessageId> message_id_from_key(std::string_view key) noexcept {
    // message_keys is sorted by the generator.
    const auto* const it = std::ranges::lower_bound(message_keys, key);
    if (it == message_keys.end() || *it != key) {
        return std::nullopt;
    }
    return static_cast<MessageId>(it - message_keys.begin());
}

std::string format_message(std::string_view pattern, std::span<const std::string> args) {
    std::string out;
    out.reserve(pattern.size());
    std::size_t i = 0;
    while (i < pattern.size()) {
        const char c = pattern[i];
        if ((c == '{' || c == '}') && i + 1 < pattern.size() && pattern[i + 1] == c) {
            out.push_back(c);
            i += 2;
            continue;
        }
        if (c == '{') {
            const auto close = pattern.find('}', i + 1);
            if (close != std::string_view::npos && close > i + 1) {
                const auto digits = pattern.substr(i + 1, close - i - 1);
                if (digits.size() <= 4 &&
                    std::ranges::all_of(digits, [](char d) { return d >= '0' && d <= '9'; })) {
                    std::size_t n = 0;
                    for (const char d : digits) {
                        n = (n * 10) + static_cast<std::size_t>(d - '0');
                    }
                    if (n < args.size()) {
                        out += args[n];
                        i = close + 1;
                        continue;
                    }
                }
            }
        }
        out.push_back(c);
        ++i;
    }
    return out;
}

} // namespace wifi_analyze
