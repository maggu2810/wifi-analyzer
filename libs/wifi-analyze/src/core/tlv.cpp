// SPDX-License-Identifier: MIT
#include <algorithm>
#include <string>

#include <wifi_analyze/tlv.hpp>

#include "core/byte_reader.hpp"
#include "core/tr.hpp"

namespace wifi_analyze {
namespace {

constexpr std::size_t header_size = 2;

Diagnostic truncated_diagnostic(std::uint8_t id, std::size_t offset, std::size_t declared,
                                std::size_t available) {
    return Diagnostic{
        .severity = Severity::error,
        .message = WA_TR(tlv_truncated,
                         "Element {0} at offset {1} declares {2} octets but only {3} remain"),
        .args = {std::to_string(id), std::to_string(offset), std::to_string(declared),
                 std::to_string(available)},
        .bytes = ByteRange{.offset = offset, .length = header_size + available},
    };
}

/// Reads one information field segment (after the 2-byte header at `offset`) into element.
/// Returns false if the stream ended early (element is then marked truncated).
bool read_segment(core::ByteReader& reader, RawElement& element, std::size_t offset,
                  std::uint8_t id, std::size_t length) {
    const auto available = std::min(length, reader.remaining());
    const auto data_offset = reader.offset();
    const auto data = reader.bytes(available).value_or(std::span<const std::uint8_t>{});
    element.payload.insert(element.payload.end(), data.begin(), data.end());
    element.payload_segments.push_back(ByteRange{.offset = data_offset, .length = available});
    if (available < length) {
        element.truncated = true;
        element.diagnostics.push_back(truncated_diagnostic(id, offset, length, available));
        return false;
    }
    return true;
}

} // namespace

ElementStream split_elements(std::span<const std::uint8_t> ies) {
    ElementStream stream;
    core::ByteReader reader{ies};

    while (!reader.empty()) {
        const auto offset = reader.offset();
        const auto header = reader.array<header_size>();
        if (!header) {
            stream.trailing = ByteRange{.offset = offset, .length = reader.remaining()};
            stream.diagnostics.push_back(Diagnostic{
                .severity = Severity::error,
                .message = WA_TR(tlv_missing_length,
                                 "Incomplete element header at offset {0}: length octet missing"),
                .args = {std::to_string(offset)},
                .bytes = stream.trailing,
            });
            reader.rest();
            break;
        }

        RawElement element;
        element.id = (*header)[0];
        const std::size_t length = (*header)[1];

        bool complete = read_segment(reader, element, offset, element.id, length);

        // Element fragmentation: a maximum-length element continued by Fragment elements, each
        // of maximum length except the last one.
        if (element.id != element_id_fragment) {
            std::size_t last_length = length;
            while (complete && last_length == element_max_length &&
                   reader.peek_u8() == element_id_fragment) {
                const auto fragment_offset = reader.offset();
                const auto fragment_header = reader.array<header_size>();
                if (!fragment_header) {
                    break; // dangling single byte, reported as trailing data by the outer loop
                }
                last_length = (*fragment_header)[1];
                complete = read_segment(reader, element, fragment_offset, element_id_fragment,
                                        last_length);
            }
            if (element.fragmented()) {
                element.diagnostics.push_back(Diagnostic{
                    .severity = Severity::info,
                    .message = WA_TR(tlv_fragmented, "Element reassembled from {0} fragments"),
                    .args = {std::to_string(element.payload_segments.size())},
                    .bytes = std::nullopt,
                });
            }
        } else {
            element.diagnostics.push_back(Diagnostic{
                .severity = Severity::warning,
                .message =
                    WA_TR(tlv_orphan_fragment,
                          "Fragment element at offset {0} does not follow a fragmentable element"),
                .args = {std::to_string(offset)},
                .bytes = ByteRange{.offset = offset, .length = header_size + length},
            });
        }

        if (element.id == element_id_extension) {
            if (element.payload.empty()) {
                element.diagnostics.push_back(Diagnostic{
                    .severity = Severity::warning,
                    .message =
                        WA_TR(tlv_extension_without_id,
                              "Extension element at offset {0} has no Element ID Extension octet"),
                    .args = {std::to_string(offset)},
                    .bytes = ByteRange{.offset = offset, .length = header_size},
                });
            } else {
                element.ext_id = element.payload.front();
            }
        }

        element.stream_range = ByteRange{.offset = offset, .length = reader.offset() - offset};
        stream.elements.push_back(std::move(element));
    }

    return stream;
}

} // namespace wifi_analyze
