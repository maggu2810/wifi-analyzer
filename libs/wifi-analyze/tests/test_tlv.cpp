// SPDX-License-Identifier: MIT
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <random>
#include <vector>

#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/tlv.hpp>

using namespace wifi_analyze;
using Bytes = std::vector<std::uint8_t>;

namespace {

Bytes hex(std::string_view text) {
    return parse_hex(text).value();
}

bool has_diagnostic(const RawElement& e, MessageId id) {
    return std::ranges::any_of(e.diagnostics, [id](const auto& d) { return d.message == id; });
}

/// Every byte of the input is covered exactly once, in order, and payload bytes match the
/// segments they claim to come from.
void check_invariants(std::span<const std::uint8_t> input, const ElementStream& stream) {
    std::size_t expected_offset = 0;
    for (const auto& e : stream.elements) {
        REQUIRE(e.stream_range.offset == expected_offset);
        REQUIRE(e.stream_range.length >= 2);
        expected_offset = e.stream_range.end();

        std::size_t payload_pos = 0;
        for (const auto& seg : e.payload_segments) {
            REQUIRE(seg.offset >= e.stream_range.offset);
            REQUIRE(seg.end() <= e.stream_range.end());
            REQUIRE(payload_pos + seg.length <= e.payload.size());
            REQUIRE(std::ranges::equal(input.subspan(seg.offset, seg.length),
                                       std::span{e.payload}.subspan(payload_pos, seg.length)));
            payload_pos += seg.length;
        }
        REQUIRE(payload_pos == e.payload.size());
        REQUIRE(e.payload.size() + (2 * e.payload_segments.size()) == e.stream_range.length);
    }
    if (stream.trailing) {
        REQUIRE(stream.trailing->offset == expected_offset);
        expected_offset = stream.trailing->end();
    }
    REQUIRE(expected_offset == input.size());
}

} // namespace

TEST_CASE("empty stream", "[tlv]") {
    const auto s = split_elements({});
    CHECK(s.elements.empty());
    CHECK(s.diagnostics.empty());
    CHECK_FALSE(s.trailing.has_value());
}

TEST_CASE("well-formed stream", "[tlv]") {
    // SSID "ab", Supported Rates (2), empty SSID-like element 7 with length 0.
    const auto input = hex("00026162 01028284 0700");
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 3);
    CHECK(s.diagnostics.empty());

    CHECK(s.elements[0].id == 0);
    CHECK(s.elements[0].payload == Bytes{'a', 'b'});
    CHECK(s.elements[0].stream_range == ByteRange{.offset = 0, .length = 4});
    CHECK(s.elements[0].payload_segments == std::vector{ByteRange{.offset = 2, .length = 2}});
    CHECK_FALSE(s.elements[0].fragmented());
    CHECK_FALSE(s.elements[0].truncated);
    CHECK(s.elements[0].diagnostics.empty());

    CHECK(s.elements[1].id == 1);
    CHECK(s.elements[2].id == 7);
    CHECK(s.elements[2].payload.empty());
}

TEST_CASE("extension element", "[tlv]") {
    const auto input = hex("ff03 23 aabb");
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 1);
    const auto& e = s.elements[0];
    CHECK(e.id == element_id_extension);
    CHECK(e.ext_id == 0x23);
    CHECK(e.payload == Bytes{0x23, 0xaa, 0xbb});
    CHECK(std::ranges::equal(e.content(), Bytes{0xaa, 0xbb}));
}

TEST_CASE("extension element without extension id", "[tlv]") {
    const auto input = hex("ff00");
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 1);
    CHECK_FALSE(s.elements[0].ext_id.has_value());
    CHECK(s.elements[0].content().empty());
    CHECK(has_diagnostic(s.elements[0], MessageId::tlv_extension_without_id));
}

TEST_CASE("truncated last element keeps available bytes", "[tlv]") {
    const auto input = hex("0001aa 3014 0100");
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 2);
    const auto& e = s.elements[1];
    CHECK(e.id == 48);
    CHECK(e.truncated);
    CHECK(e.payload == Bytes{0x01, 0x00});
    REQUIRE(e.diagnostics.size() == 1);
    CHECK(e.diagnostics[0].message == MessageId::tlv_truncated);
    CHECK(e.diagnostics[0].args == std::vector<std::string>{"48", "3", "20", "2"});
}

TEST_CASE("dangling header byte is reported as trailing", "[tlv]") {
    const auto input = hex("0001aa dd");
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 1);
    CHECK(s.trailing == ByteRange{.offset = 3, .length = 1});
    REQUIRE(s.diagnostics.size() == 1);
    CHECK(s.diagnostics[0].message == MessageId::tlv_missing_length);
}

TEST_CASE("fragmented element is reassembled", "[tlv]") {
    // Vendor element with 255 + 255 + 3 payload bytes, followed by an SSID.
    Bytes input{element_id_vendor_specific, 0xff};
    input.insert(input.end(), 255, 0x11);
    input.insert(input.end(), {element_id_fragment, 0xff});
    input.insert(input.end(), 255, 0x22);
    input.insert(input.end(), {element_id_fragment, 0x03, 0x33, 0x33, 0x33});
    input.insert(input.end(), {0x00, 0x00});

    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 2);
    const auto& e = s.elements[0];
    CHECK(e.id == element_id_vendor_specific);
    CHECK(e.fragmented());
    CHECK(e.payload.size() == 513);
    CHECK(e.payload[254] == 0x11);
    CHECK(e.payload[255] == 0x22);
    CHECK(e.payload[510] == 0x33);
    CHECK(e.payload_segments.size() == 3);
    CHECK(e.stream_range == ByteRange{.offset = 0, .length = 519});
    CHECK(has_diagnostic(e, MessageId::tlv_fragmented));
    CHECK(s.elements[1].id == 0);
}

TEST_CASE("fragmented extension element keeps extension id", "[tlv]") {
    Bytes input{element_id_extension, 0xff, 0x6b};
    input.insert(input.end(), 254, 0x01);
    input.insert(input.end(), {element_id_fragment, 0x01, 0x02});
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 1);
    CHECK(s.elements[0].ext_id == 0x6b);
    CHECK(s.elements[0].content().size() == 255);
}

TEST_CASE("fragment chain ends after a non-maximum fragment", "[tlv]") {
    Bytes input{0xdd, 0xff};
    input.insert(input.end(), 255, 0x00);
    input.insert(input.end(), {element_id_fragment, 0x01, 0xaa});
    input.insert(input.end(), {element_id_fragment, 0x01, 0xbb}); // orphan
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 2);
    CHECK(s.elements[0].payload.size() == 256);
    CHECK(s.elements[1].id == element_id_fragment);
    CHECK(has_diagnostic(s.elements[1], MessageId::tlv_orphan_fragment));
}

TEST_CASE("orphan fragment and non-fragmented 255-length element", "[tlv]") {
    Bytes input{element_id_fragment, 0x01, 0xaa, 0x00, 0xff};
    input.insert(input.end(), 255, 0x00);
    input.insert(input.end(), {0x01, 0x01, 0x82});
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 3);
    CHECK(has_diagnostic(s.elements[0], MessageId::tlv_orphan_fragment));
    CHECK_FALSE(s.elements[1].fragmented());
    CHECK(s.elements[2].id == 1);
}

TEST_CASE("truncated fragment", "[tlv]") {
    Bytes input{0xdd, 0xff};
    input.insert(input.end(), 255, 0x00);
    input.insert(input.end(), {element_id_fragment, 0x10, 0xaa});
    const auto s = split_elements(input);
    check_invariants(input, s);
    REQUIRE(s.elements.size() == 1);
    CHECK(s.elements[0].truncated);
    CHECK(s.elements[0].payload.size() == 256);
}

TEST_CASE("random streams uphold the coverage invariant", "[tlv][property]") {
    std::mt19937 rng{20261026};
    std::uniform_int_distribution<int> length_dist{0, 600};
    std::uniform_int_distribution<int> byte_dist{0, 255};
    for (int iteration = 0; iteration < 5000; ++iteration) {
        Bytes input(static_cast<std::size_t>(length_dist(rng)));
        // Bias towards interesting ids so fragmentation and extensions get exercised.
        for (auto& b : input) {
            const int r = byte_dist(rng);
            if (r < 16) {
                b = element_id_extension;
            } else if (r < 32) {
                b = element_id_fragment;
            } else {
                b = static_cast<std::uint8_t>(r);
            }
        }
        const auto s = split_elements(input);
        check_invariants(input, s);
    }
}
