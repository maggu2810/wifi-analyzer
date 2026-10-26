// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <wifi_analyze/common.hpp>
#include <wifi_analyze/message_id.hpp>

namespace wifi_analyze {

class Localizer;

/// Display text: either a translatable message or a fixed technical name (e.g. "CCMP-128")
/// that is never translated. Literals must have static storage duration.
class Text {
public:
    constexpr Text() noexcept = default;
    // Implicit by design: tables mix messages and technical literals.
    constexpr Text(MessageId id) noexcept : value_{id} {} // NOLINT(*-explicit-constructor)
    constexpr Text(const char* literal) noexcept          // NOLINT(*-explicit-constructor)
        : value_{std::string_view{literal}} {}

    [[nodiscard]] constexpr bool empty() const noexcept {
        return std::holds_alternative<std::monostate>(value_);
    }
    [[nodiscard]] constexpr const MessageId* message() const noexcept {
        return std::get_if<MessageId>(&value_);
    }
    [[nodiscard]] constexpr const std::string_view* literal() const noexcept {
        return std::get_if<std::string_view>(&value_);
    }
    [[nodiscard]] std::string_view render(const Localizer& localizer) const noexcept;

    friend constexpr bool operator==(const Text&, const Text&) = default;

private:
    std::variant<std::monostate, MessageId, std::string_view> value_;
};

/// A numeric code together with its meaning.
struct EnumValue {
    std::uint64_t raw{0};
    Text name;
    friend bool operator==(const EnumValue&, const EnumValue&) = default;
};

using Value = std::variant<std::monostate, bool, std::int64_t, std::uint64_t, double, std::string,
                           std::vector<std::uint8_t>, EnumValue>;

enum class Unit : std::uint8_t {
    none,
    dbm,
    db,
    dbm_per_mhz,
    mhz,
    mbps,
    kbps,
    tu, ///< time unit, 1024 µs
    microseconds,
    milliseconds,
    percent,
    octets,
};

enum class Display : std::uint8_t {
    decimal,
    hex,
    suite,     ///< cipher/AKM suite selector "00-0f-ac:4" (raw = OUI << 8 | type)
    name_only, ///< enumerations: show the name without the raw value
};

enum class Significance : std::uint8_t {
    normal,
    detail,  ///< low-value detail (e.g. unset capability bits); frontends may hide it
    warning, ///< noteworthy, e.g. insecure configuration
};

/// Bits within the bytes of a node, numbered LSB-first from the first byte (IEEE 802.11 "B0").
struct BitRange {
    std::uint16_t first{0};
    std::uint16_t count{1};
    friend constexpr bool operator==(const BitRange&, const BitRange&) = default;
};

/// Presentation-neutral description of decoded data. Every frontend renders this generically.
struct TreeNode {
    /// Label; message_key(label) is the stable machine key of the field.
    MessageId label{};
    Value value;
    Unit unit{Unit::none};
    Display display{Display::decimal};
    /// Source bytes, relative to the element content (see DecodedElement::content()).
    std::optional<ByteRange> bytes;
    std::optional<BitRange> bits;
    Significance significance{Significance::normal};
    std::vector<TreeNode> children;
};

/// Human readable value of a node, e.g. "CCMP-128 (4)", "-49 dBm", "yes", "0x000c".
[[nodiscard]] std::string format_value(const TreeNode& node, const Localizer& localizer);

/// Unit symbol (never translated), empty for Unit::none.
[[nodiscard]] std::string_view unit_symbol(Unit unit) noexcept;

/// Shifts all byte ranges of a tree by `offset` (used when embedding nested element trees).
void shift_bytes(TreeNode& node, std::size_t offset);

} // namespace wifi_analyze
