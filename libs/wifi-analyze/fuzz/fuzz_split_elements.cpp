// SPDX-License-Identifier: MIT
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include <wifi_analyze/tlv.hpp>

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

// Checks that every input byte is covered exactly once and payloads match their segments.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::uint8_t> input{data, size};
    const auto stream = wifi_analyze::split_elements(input);

    std::size_t expected = 0;
    for (const auto& element : stream.elements) {
        require(element.stream_range.offset == expected);
        expected = element.stream_range.end();
        std::size_t pos = 0;
        for (const auto& segment : element.payload_segments) {
            require(segment.end() <= element.stream_range.end());
            for (std::size_t i = 0; i < segment.length; ++i) {
                require(input[segment.offset + i] == element.payload.at(pos + i));
            }
            pos += segment.length;
        }
        require(pos == element.payload.size());
        require(element.content().size() <= element.payload.size());
    }
    if (stream.trailing) {
        require(stream.trailing->offset == expected);
        expected = stream.trailing->end();
    }
    require(expected == size);
    return 0;
}
