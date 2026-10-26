// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <vector>

#include <wifi_analyze/hex.hpp>

using namespace wifi_analyze;
using Bytes = std::vector<std::uint8_t>;

TEST_CASE("parse_hex accepts common notations", "[hex]") {
    CHECK(parse_hex("00094a4b") == Bytes{0x00, 0x09, 0x4a, 0x4b});
    CHECK(parse_hex("0x00094A4B") == Bytes{0x00, 0x09, 0x4a, 0x4b});
    CHECK(parse_hex("  00 09 4a\n4b\t") == Bytes{0x00, 0x09, 0x4a, 0x4b});
    CHECK(parse_hex("00:11:22:aa") == Bytes{0x00, 0x11, 0x22, 0xaa});
    CHECK(parse_hex("00-11-22") == Bytes{0x00, 0x11, 0x22});
    CHECK(parse_hex("") == Bytes{});
    CHECK(parse_hex("   ") == Bytes{});
    CHECK(parse_hex("0x") == Bytes{});
}

TEST_CASE("parse_hex reports invalid characters with position", "[hex]") {
    const auto result = parse_hex("00 0g");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message == MessageId::hex_invalid_character);
    CHECK(result.error().args == std::vector<std::string>{"g", "4"});
    CHECK(result.error().bytes == ByteRange{.offset = 4, .length = 1});

    const auto control = parse_hex("00\x01");
    REQUIRE_FALSE(control.has_value());
    CHECK(control.error().args.front() == "\\x01");

    // "ie=" prefixes are handled by input-format parsers, not here.
    CHECK_FALSE(parse_hex("ie=0000").has_value());
}

TEST_CASE("parse_hex reports odd digit count", "[hex]") {
    const auto result = parse_hex("000");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().message == MessageId::hex_odd_length);
    CHECK(result.error().args == std::vector<std::string>{"3"});
}

TEST_CASE("to_hex round-trips", "[hex]") {
    const Bytes bytes{0x00, 0x0f, 0xac, 0xff};
    CHECK(to_hex(bytes) == "000facff");
    CHECK(parse_hex(to_hex(bytes)) == bytes);
    CHECK(to_hex({}).empty());
}
