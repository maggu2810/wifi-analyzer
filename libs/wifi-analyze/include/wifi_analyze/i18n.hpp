// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <wifi_analyze/message_id.hpp>

namespace wifi_analyze {

/// Renders domain messages in one locale, falling back to English per message.
/// Cheap to copy; refers to static catalog data only.
class Localizer {
public:
    /// English.
    Localizer() noexcept;

    /// Locale of the selected catalog ("en", "de", ...).
    [[nodiscard]] std::string_view locale() const noexcept;

    /// Message text with unresolved placeholders.
    [[nodiscard]] std::string_view text(MessageId id) const noexcept;

    /// Message text with placeholders {0}, {1}, ... replaced by args.
    [[nodiscard]] std::string format(MessageId id, std::span<const std::string> args = {}) const;

private:
    friend Localizer localizer(std::string_view locale) noexcept;
    explicit Localizer(std::size_t catalog_index) noexcept : catalog_{catalog_index} {}

    std::size_t catalog_{0};
};

/// Selects the best catalog for a locale string such as "de", "de_DE", "de-DE",
/// "de_DE.UTF-8@euro". Unknown, empty, "C" and "POSIX" select English.
[[nodiscard]] Localizer localizer(std::string_view locale) noexcept;

/// Locales with a catalog, English first.
[[nodiscard]] std::span<const std::string_view> available_locales() noexcept;

/// Stable key of a message, e.g. "tlv.truncated".
[[nodiscard]] std::string_view message_key(MessageId id) noexcept;

/// Reverse lookup of message_key().
[[nodiscard]] std::optional<MessageId> message_id_from_key(std::string_view key) noexcept;

/// Replaces positional placeholders {N} in pattern with args[N]. "{{" and "}}" produce literal
/// braces; placeholders without a matching argument are kept verbatim.
[[nodiscard]] std::string format_message(std::string_view pattern,
                                         std::span<const std::string> args);

} // namespace wifi_analyze
