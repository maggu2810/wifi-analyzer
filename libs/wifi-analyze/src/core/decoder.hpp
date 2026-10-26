// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <wifi_analyze/ie.hpp>
#include <wifi_analyze/tree.hpp>

#include "core/byte_reader.hpp"
#include "core/tr.hpp"

namespace wifi_analyze::core {

using NameFn = Text (*)(std::uint64_t);

/// Looks up a name in a dense table; out-of-range values are "Reserved".
template <std::size_t N>
constexpr Text table_name(const std::array<Text, N>& table, std::uint64_t value) noexcept {
    if (value < N && !table[value].empty()) {
        return table[value];
    }
    return msg::reserved;
}

/// A fixed-width bit field read from the content; children describe individual bits.
class BitField {
public:
    BitField(TreeNode node, std::vector<std::uint8_t> data) noexcept
        : node_{std::move(node)}, data_{std::move(data)} {}

    /// Bits [first, first + count) as integer (count <= 64), LSB-first numbering.
    [[nodiscard]] std::uint64_t get(unsigned first, unsigned count) const noexcept;
    [[nodiscard]] bool test(unsigned bit) const noexcept { return get(bit, 1) != 0; }
    [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return data_; }

    /// Adds a boolean child for one bit. Unset bits get Significance::detail if requested.
    bool flag(unsigned bit, MessageId label, bool detail_if_unset = false);
    /// Adds a numeric child; `value` is the raw field plus `add` (e.g. "NSS - 1" encodings).
    std::uint64_t number(unsigned first, unsigned count, MessageId label, Unit unit = Unit::none,
                         std::uint64_t add = 0);
    /// Adds an enumerated child.
    std::uint64_t enumeration(unsigned first, unsigned count, MessageId label, NameFn names);
    /// Adds a child with an explicitly computed value.
    void computed(unsigned first, unsigned count, MessageId label, Value value,
                  Unit unit = Unit::none);

    TreeNode& node() noexcept { return node_; }
    TreeNode take() noexcept { return std::move(node_); }

private:
    TreeNode& add_child(unsigned first, unsigned count, MessageId label, Value value, Unit unit);

    TreeNode node_;
    std::vector<std::uint8_t> data_;
};

/// Per-element decoding state: reader over the element content, tree root and diagnostics.
/// Field helpers read a value, append a node with its byte range to `parent` and return the
/// value; when the content is too short they mark the element malformed and return nullopt.
class Decoder {
public:
    Decoder(std::span<const std::uint8_t> content, const DecodeContext& context,
            std::span<const DecodedElement> previous, unsigned depth);

    [[nodiscard]] ByteReader& reader() noexcept { return reader_; }
    [[nodiscard]] std::size_t offset() const noexcept { return reader_.offset(); }
    [[nodiscard]] std::size_t remaining() const noexcept { return reader_.remaining(); }
    [[nodiscard]] std::span<const std::uint8_t> content() const noexcept { return content_; }
    [[nodiscard]] const DecodeContext& context() const noexcept { return context_; }
    [[nodiscard]] unsigned depth() const noexcept { return depth_; }
    [[nodiscard]] ByteRange range_from(std::size_t start) const noexcept {
        return ByteRange{.offset = start, .length = offset() - start};
    }

    [[nodiscard]] TreeNode& root() noexcept { return root_; }
    void add(TreeNode node) { root_.children.push_back(std::move(node)); }

    /// A previously decoded element of the same stream with typed value T, or nullptr.
    template <class T>
    [[nodiscard]] const T* previous() const noexcept {
        for (const auto& e : previous_) {
            if (const auto* v = std::get_if<T>(&e.value)) {
                return v;
            }
        }
        return nullptr;
    }

    // --- diagnostics -------------------------------------------------------------------
    /// Marks the element as shorter than its format requires (adds a diagnostic once).
    void malformed();
    [[nodiscard]] bool is_malformed() const noexcept { return malformed_; }
    void diagnostic(Severity severity, MessageId message, std::vector<std::string> args = {},
                    std::optional<ByteRange> bytes = std::nullopt);
    void warn_node(TreeNode& node, Severity severity, MessageId message,
                   std::vector<std::string> args = {});
    [[nodiscard]] std::vector<Diagnostic> take_diagnostics() noexcept {
        return std::move(diagnostics_);
    }

    // --- node construction -------------------------------------------------------------
    [[nodiscard]] static TreeNode node(MessageId label, Value value = {},
                                       std::optional<ByteRange> bytes = std::nullopt,
                                       Unit unit = Unit::none);
    /// A group node whose byte range is set by close().
    [[nodiscard]] TreeNode group(MessageId label) const;
    void close(TreeNode& group, std::size_t start) const { group.bytes = range_from(start); }

    // --- field helpers -------------------------------------------------------------------
    std::optional<std::uint8_t> u8(TreeNode& parent, MessageId label, Unit unit = Unit::none,
                                   Display display = Display::decimal);
    std::optional<std::uint16_t> u16(TreeNode& parent, MessageId label, Unit unit = Unit::none,
                                     Display display = Display::decimal);
    std::optional<std::uint32_t> u32(TreeNode& parent, MessageId label, Unit unit = Unit::none,
                                     Display display = Display::decimal);
    std::optional<std::int8_t> s8(TreeNode& parent, MessageId label, Unit unit = Unit::none);
    /// Reads a little-endian integer of `size` octets and adds it as enumerated value.
    std::optional<std::uint64_t> enumeration(TreeNode& parent, MessageId label, std::size_t size,
                                             NameFn names);
    std::optional<std::span<const std::uint8_t>> bytes(TreeNode& parent, MessageId label,
                                                       std::size_t size);
    std::optional<MacAddress> mac(TreeNode& parent, MessageId label);
    /// OUI with vendor name.
    std::optional<Oui> oui(TreeNode& parent, MessageId label);
    /// Text field of `size` octets (UTF-8 if valid, otherwise escaped).
    std::optional<std::string> text(TreeNode& parent, MessageId label, std::size_t size);
    /// Reads `size` octets as a bit field; add the returned group with parent.children after
    /// describing the bits.
    std::optional<BitField> bits(MessageId label, std::size_t size, Display display = Display::hex);
    /// All remaining octets as one node (nothing added if empty).
    std::span<const std::uint8_t> rest(TreeNode& parent, MessageId label);

    /// Decodes `data` (located at content offset `base`) as a sequence of elements and adds
    /// one node per element to `parent`. Returns the nested decode result.
    DecodedIes nested_elements(TreeNode& parent, std::span<const std::uint8_t> data,
                               std::size_t base);

private:
    std::span<const std::uint8_t> content_;
    ByteReader reader_;
    const DecodeContext& context_;
    std::span<const DecodedElement> previous_;
    unsigned depth_;
    TreeNode root_;
    std::vector<Diagnostic> diagnostics_;
    bool malformed_{false};
};

/// Formats a MAC address "aa:bb:cc:dd:ee:ff".
[[nodiscard]] std::string format_mac(std::span<const std::uint8_t> mac);
/// Formats an OUI "00:0f:ac".
[[nodiscard]] std::string format_oui(const Oui& oui);
/// UTF-8 text if valid and printable, otherwise escaped ("\xNN").
[[nodiscard]] std::string display_text(std::span<const std::uint8_t> bytes);
/// OUI as 24-bit integer.
[[nodiscard]] constexpr std::uint32_t oui_value(const Oui& oui) noexcept {
    return (static_cast<std::uint32_t>(oui[0]) << 16U) |
           (static_cast<std::uint32_t>(oui[1]) << 8U) | oui[2];
}

/// Decodes a stream at a given nesting depth (decode() uses depth 0).
[[nodiscard]] DecodedIes decode_elements(std::span<const std::uint8_t> ies,
                                         const DecodeContext& context, unsigned depth);

} // namespace wifi_analyze::core
