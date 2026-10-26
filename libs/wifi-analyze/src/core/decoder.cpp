// SPDX-License-Identifier: MIT
#include "core/decoder.hpp"

#include <algorithm>
#include <string>

#include <wifi_analyze/oui.hpp>

#include "core/registry.hpp"

namespace wifi_analyze::core {
namespace {

constexpr std::string_view hex_digits = "0123456789abcdef";

/// Validates UTF-8 (no overlong forms, no surrogates, max U+10FFFF).
bool valid_utf8(std::span<const std::uint8_t> s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const std::uint8_t c = s[i];
        std::size_t len = 0;
        std::uint32_t cp = 0;
        if (c < 0x80) {
            ++i;
            continue;
        }
        if ((c & 0xe0U) == 0xc0U) {
            len = 2;
            cp = c & 0x1fU;
        } else if ((c & 0xf0U) == 0xe0U) {
            len = 3;
            cp = c & 0x0fU;
        } else if ((c & 0xf8U) == 0xf0U) {
            len = 4;
            cp = c & 0x07U;
        } else {
            return false;
        }
        if (i + len > s.size()) {
            return false;
        }
        for (std::size_t k = 1; k < len; ++k) {
            if ((s[i + k] & 0xc0U) != 0x80U) {
                return false;
            }
            cp = (cp << 6U) | (s[i + k] & 0x3fU);
        }
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000) ||
            cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
            return false;
        }
        i += len;
    }
    return true;
}

void append_escaped(std::string& out, std::uint8_t b) {
    out += "\\x";
    out.push_back(hex_digits[b >> 4U]);
    out.push_back(hex_digits[b & 0xfU]);
}

std::size_t content_stream_offset(const RawElement& raw) {
    if (raw.payload_segments.empty()) {
        return raw.stream_range.offset + 2;
    }
    return raw.payload_segments.front().offset + (raw.ext_id ? 1 : 0);
}

DecodedElement decode_element(RawElement raw, const DecodeContext& context,
                              std::span<const DecodedElement> previous, unsigned depth) {
    DecodedElement element;
    element.key.id = raw.id;
    element.key.ext_id = raw.ext_id;
    element.diagnostics = raw.diagnostics;

    const auto content = raw.content();
    Decoder d{content, context, previous, depth};
    DecodeFn fn = nullptr;

    if (raw.id == element_id_vendor_specific) {
        element.type = "vendor";
        element.name = WA_TR(element_vendor_specific, "Vendor Specific");
        if (const auto oui = d.oui(d.root(), WA_TR(vendor_oui, "OUI"))) {
            element.key.oui = *oui;
            element.key.vendor_type = d.reader().peek_u8();
            if (const auto* entry = find_vendor(*oui, element.key.vendor_type)) {
                element.type = entry->type;
                element.name = entry->name;
                fn = entry->fn;
            }
        }
    } else if (raw.id == element_id_extension) {
        element.type = "extension";
        element.name = WA_TR(element_unknown_extension, "Unknown Extension Element");
        if (raw.ext_id) {
            if (const auto* entry = find_extension(*raw.ext_id)) {
                element.type = entry->type;
                element.name = entry->name;
                fn = entry->fn;
            }
        }
    } else {
        element.type = "unknown";
        element.name = WA_TR(element_unknown, "Unknown Element");
        if (const auto* entry = find_standard(raw.id)) {
            element.type = entry->type;
            element.name = entry->name;
            fn = entry->fn;
        }
    }

    if (fn != nullptr) {
        element.value = fn(d);
        element.status = d.is_malformed() ? DecodeStatus::malformed : DecodeStatus::ok;
        if (!d.is_malformed() && d.remaining() > 0) {
            const auto start = d.offset();
            const auto extra = d.rest(d.root(), WA_TR(common_unparsed, "Unparsed Data"));
            d.diagnostic(Severity::warning,
                         WA_TR(decode_trailing_data,
                               "{0} octets after the known fields were not interpreted"),
                         {std::to_string(extra.size())},
                         ByteRange{.offset = start, .length = extra.size()});
        }
    } else {
        element.status = DecodeStatus::unknown;
        d.rest(d.root(), msg::data);
    }
    if (raw.truncated) {
        element.status = DecodeStatus::truncated;
    }

    element.tree = std::move(d.root());
    element.tree.label = element.name;
    element.tree.bytes = ByteRange{.offset = 0, .length = content.size()};

    // Decoder diagnostics are content-relative; make them stream-relative.
    const auto base = content_stream_offset(raw);
    for (auto diag : d.take_diagnostics()) {
        if (diag.bytes) {
            diag.bytes->offset += base;
        }
        element.diagnostics.push_back(std::move(diag));
    }
    element.raw = std::move(raw);
    return element;
}

} // namespace

// --- BitField ----------------------------------------------------------------------------

std::uint64_t BitField::get(unsigned first, unsigned count) const noexcept {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < count && i < 64; ++i) {
        const unsigned bit = first + i;
        if (bit / 8 < data_.size() && ((data_[bit / 8] >> (bit % 8)) & 1U) != 0) {
            value |= (std::uint64_t{1} << i);
        }
    }
    return value;
}

TreeNode& BitField::add_child(unsigned first, unsigned count, MessageId label, Value value,
                              Unit unit) {
    TreeNode child;
    child.label = label;
    child.value = std::move(value);
    child.unit = unit;
    child.bytes = node_.bytes;
    child.bits = BitRange{.first = static_cast<std::uint16_t>(first),
                          .count = static_cast<std::uint16_t>(count)};
    return node_.children.emplace_back(std::move(child));
}

bool BitField::flag(unsigned bit, MessageId label, bool detail_if_unset) {
    const bool set = test(bit);
    auto& child = add_child(bit, 1, label, set, Unit::none);
    if (!set && detail_if_unset) {
        child.significance = Significance::detail;
    }
    return set;
}

std::uint64_t BitField::number(unsigned first, unsigned count, MessageId label, Unit unit,
                               std::uint64_t add) {
    const auto raw = get(first, count);
    add_child(first, count, label, raw + add, unit);
    return raw;
}

std::uint64_t BitField::enumeration(unsigned first, unsigned count, MessageId label, NameFn names) {
    const auto raw = get(first, count);
    add_child(first, count, label, EnumValue{.raw = raw, .name = names(raw)}, Unit::none);
    return raw;
}

void BitField::computed(unsigned first, unsigned count, MessageId label, Value value, Unit unit) {
    add_child(first, count, label, std::move(value), unit);
}

// --- Decoder -----------------------------------------------------------------------------

Decoder::Decoder(std::span<const std::uint8_t> content, const DecodeContext& context,
                 std::span<const DecodedElement> previous, unsigned depth)
    : content_{content}, reader_{content}, context_{context}, previous_{previous}, depth_{depth} {}

void Decoder::malformed() {
    if (!malformed_) {
        malformed_ = true;
        diagnostic(Severity::error,
                   WA_TR(decode_too_short, "Element content ends unexpectedly at octet {0}"),
                   {std::to_string(offset())}, ByteRange{.offset = offset(), .length = 0});
    }
}

void Decoder::diagnostic(Severity severity, MessageId message, std::vector<std::string> args,
                         std::optional<ByteRange> bytes) {
    diagnostics_.push_back(Diagnostic{
        .severity = severity, .message = message, .args = std::move(args), .bytes = bytes});
}

void Decoder::warn_node(TreeNode& node, Severity severity, MessageId message,
                        std::vector<std::string> args) {
    node.significance = Significance::warning;
    diagnostic(severity, message, std::move(args), node.bytes);
}

TreeNode Decoder::node(MessageId label, Value value, std::optional<ByteRange> bytes, Unit unit) {
    TreeNode n;
    n.label = label;
    n.value = std::move(value);
    n.bytes = bytes;
    n.unit = unit;
    return n;
}

TreeNode Decoder::group(MessageId label) const {
    return node(label, {}, ByteRange{.offset = offset(), .length = 0});
}

std::optional<std::uint8_t> Decoder::u8(TreeNode& parent, MessageId label, Unit unit,
                                        Display display) {
    const auto start = offset();
    const auto v = reader_.u8();
    if (!v) {
        malformed();
        return std::nullopt;
    }
    auto n = node(label, std::uint64_t{*v}, range_from(start), unit);
    n.display = display;
    parent.children.push_back(std::move(n));
    return v;
}

std::optional<std::uint16_t> Decoder::u16(TreeNode& parent, MessageId label, Unit unit,
                                          Display display) {
    const auto start = offset();
    const auto v = reader_.u16le();
    if (!v) {
        malformed();
        return std::nullopt;
    }
    auto n = node(label, std::uint64_t{*v}, range_from(start), unit);
    n.display = display;
    parent.children.push_back(std::move(n));
    return v;
}

std::optional<std::uint32_t> Decoder::u32(TreeNode& parent, MessageId label, Unit unit,
                                          Display display) {
    const auto start = offset();
    const auto v = reader_.u32le();
    if (!v) {
        malformed();
        return std::nullopt;
    }
    auto n = node(label, std::uint64_t{*v}, range_from(start), unit);
    n.display = display;
    parent.children.push_back(std::move(n));
    return v;
}

std::optional<std::int8_t> Decoder::s8(TreeNode& parent, MessageId label, Unit unit) {
    const auto start = offset();
    const auto v = reader_.u8();
    if (!v) {
        malformed();
        return std::nullopt;
    }
    const auto s = static_cast<std::int8_t>(*v);
    parent.children.push_back(node(label, std::int64_t{s}, range_from(start), unit));
    return s;
}

std::optional<std::uint64_t> Decoder::enumeration(TreeNode& parent, MessageId label,
                                                  std::size_t size, NameFn names) {
    const auto start = offset();
    const auto data = reader_.bytes(size);
    if (!data || size > 8) {
        malformed();
        return std::nullopt;
    }
    std::uint64_t raw = 0;
    for (std::size_t i = 0; i < size; ++i) {
        raw |= std::uint64_t{(*data)[i]} << (8U * i);
    }
    parent.children.push_back(
        node(label, EnumValue{.raw = raw, .name = names(raw)}, range_from(start)));
    return raw;
}

std::optional<std::span<const std::uint8_t>> Decoder::bytes(TreeNode& parent, MessageId label,
                                                            std::size_t size) {
    const auto start = offset();
    const auto data = reader_.bytes(size);
    if (!data) {
        malformed();
        return std::nullopt;
    }
    parent.children.push_back(
        node(label, std::vector<std::uint8_t>(data->begin(), data->end()), range_from(start)));
    return data;
}

std::optional<MacAddress> Decoder::mac(TreeNode& parent, MessageId label) {
    const auto start = offset();
    const auto data = reader_.array<6>();
    if (!data) {
        malformed();
        return std::nullopt;
    }
    parent.children.push_back(node(label, format_mac(*data), range_from(start)));
    return data;
}

std::optional<Oui> Decoder::oui(TreeNode& parent, MessageId label) {
    const auto start = offset();
    const auto data = reader_.array<3>();
    if (!data) {
        malformed();
        return std::nullopt;
    }
    auto n = node(label, format_oui(*data), range_from(start));
    if (const auto name = oui_name(*data, context_.oui_database)) {
        n.children.push_back(
            node(WA_TR(vendor_name, "Vendor"), std::string{*name}, range_from(start)));
    }
    parent.children.push_back(std::move(n));
    return data;
}

std::optional<std::string> Decoder::text(TreeNode& parent, MessageId label, std::size_t size) {
    const auto start = offset();
    const auto data = reader_.bytes(size);
    if (!data) {
        malformed();
        return std::nullopt;
    }
    auto s = display_text(*data);
    parent.children.push_back(node(label, s, range_from(start)));
    return s;
}

std::optional<BitField> Decoder::bits(MessageId label, std::size_t size, Display display) {
    const auto start = offset();
    const auto data = reader_.bytes(size);
    if (!data) {
        malformed();
        return std::nullopt;
    }
    std::vector<std::uint8_t> copy(data->begin(), data->end());
    TreeNode n;
    if (size <= 8) {
        std::uint64_t raw = 0;
        for (std::size_t i = 0; i < size; ++i) {
            raw |= std::uint64_t{copy[i]} << (8U * i);
        }
        n = node(label, raw, range_from(start));
        n.display = display;
    } else {
        n = node(label, copy, range_from(start));
    }
    return BitField{std::move(n), std::move(copy)};
}

std::span<const std::uint8_t> Decoder::rest(TreeNode& parent, MessageId label) {
    const auto start = offset();
    const auto data = reader_.rest();
    if (!data.empty()) {
        parent.children.push_back(
            node(label, std::vector<std::uint8_t>(data.begin(), data.end()), range_from(start)));
    }
    return data;
}

DecodedIes Decoder::nested_elements(TreeNode& parent, std::span<const std::uint8_t> data,
                                    std::size_t base) {
    if (depth_ + 1 > context_.max_depth) {
        parent.children.push_back(node(msg::data,
                                       std::vector<std::uint8_t>(data.begin(), data.end()),
                                       ByteRange{.offset = base, .length = data.size()}));
        diagnostic(Severity::warning,
                   WA_TR(decode_max_depth, "Nested elements not decoded: maximum depth reached"),
                   {}, ByteRange{.offset = base, .length = data.size()});
        return {};
    }
    auto nested = decode_elements(data, context_, depth_ + 1);
    for (const auto& e : nested.elements) {
        TreeNode n = e.tree;
        shift_bytes(n, base + content_stream_offset(e.raw));
        parent.children.push_back(std::move(n));
        for (auto diag : e.diagnostics) {
            if (diag.bytes) {
                diag.bytes->offset += base;
            }
            diagnostics_.push_back(std::move(diag));
        }
    }
    for (auto diag : nested.diagnostics) {
        if (diag.bytes) {
            diag.bytes->offset += base;
        }
        diagnostics_.push_back(std::move(diag));
    }
    return nested;
}

ElementValue Decoder::sub_decode(TreeNode& parent, SubDecodeFn fn,
                                 std::span<const std::uint8_t> data, std::size_t base) {
    if (depth_ + 1 > context_.max_depth) {
        parent.children.push_back(node(msg::data,
                                       std::vector<std::uint8_t>(data.begin(), data.end()),
                                       ByteRange{.offset = base, .length = data.size()}));
        return {};
    }
    Decoder sub{data, context_, {}, depth_ + 1};
    auto value = fn(sub);
    if (!sub.is_malformed() && sub.remaining() > 0) {
        sub.rest(sub.root(), WA_TR(common_unparsed, "Unparsed Data"));
    }
    for (auto& child : sub.root().children) {
        shift_bytes(child, base);
        parent.children.push_back(std::move(child));
    }
    for (auto diag : sub.take_diagnostics()) {
        if (diag.bytes) {
            diag.bytes->offset += base;
        }
        diagnostics_.push_back(std::move(diag));
    }
    return value;
}

// --- free functions ----------------------------------------------------------------------

std::string format_mac(std::span<const std::uint8_t> mac) {
    std::string out;
    for (std::size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) {
            out.push_back(':');
        }
        out.push_back(hex_digits[mac[i] >> 4U]);
        out.push_back(hex_digits[mac[i] & 0xfU]);
    }
    return out;
}

std::string format_oui(const Oui& oui) {
    return format_mac(oui);
}

std::string display_text(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size());
    const bool utf8 = valid_utf8(bytes);
    for (const auto b : bytes) {
        if (b == '\\') {
            out += "\\\\";
        } else if (b < 0x20 || b == 0x7f || (!utf8 && b >= 0x80)) {
            append_escaped(out, b);
        } else {
            out.push_back(static_cast<char>(b));
        }
    }
    return out;
}

DecodedIes decode_elements(std::span<const std::uint8_t> ies, const DecodeContext& context,
                           unsigned depth) {
    auto stream = split_elements(ies);
    DecodedIes result;
    result.diagnostics = std::move(stream.diagnostics);
    result.trailing = stream.trailing;
    result.elements.reserve(stream.elements.size());
    for (auto& raw : stream.elements) {
        auto element = decode_element(std::move(raw), context, result.elements, depth);
        result.elements.push_back(std::move(element));
    }
    return result;
}

} // namespace wifi_analyze::core

namespace wifi_analyze {

DecodedIes decode(std::span<const std::uint8_t> ies, const DecodeContext& context) {
    return core::decode_elements(ies, context, 0);
}

std::vector<ElementInfo> known_elements() {
    std::vector<ElementInfo> result;
    for (const auto& e : core::standard_entries()) {
        result.push_back(
            ElementInfo{.key = ElementKey{.id = e.id, .ext_id = {}, .oui = {}, .vendor_type = {}},
                        .type = e.type,
                        .name = e.name,
                        .spec_reference = e.spec,
                        .decoded = e.fn != nullptr});
    }
    for (const auto& e : core::extension_entries()) {
        result.push_back(ElementInfo{.key = ElementKey{.id = element_id_extension,
                                                       .ext_id = e.id,
                                                       .oui = {},
                                                       .vendor_type = {}},
                                     .type = e.type,
                                     .name = e.name,
                                     .spec_reference = e.spec,
                                     .decoded = e.fn != nullptr});
    }
    for (const auto& e : core::vendor_entries()) {
        result.push_back(ElementInfo{.key = ElementKey{.id = element_id_vendor_specific,
                                                       .ext_id = {},
                                                       .oui = e.oui,
                                                       .vendor_type = e.vendor_type},
                                     .type = e.type,
                                     .name = e.name,
                                     .spec_reference = e.spec,
                                     .decoded = e.fn != nullptr});
    }
    return result;
}

} // namespace wifi_analyze
