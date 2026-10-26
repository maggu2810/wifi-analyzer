// SPDX-License-Identifier: MIT
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>

#include "core/byte_reader.hpp"

using wifi_analyze::core::ByteReader;

namespace {
constexpr std::array<std::uint8_t, 9> data{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
} // namespace

TEST_CASE("ByteReader reads little and big endian integers", "[byte_reader]") {
    ByteReader r{data};
    CHECK(r.u8() == 0x01);
    CHECK(r.u16le() == 0x0302);
    CHECK(r.offset() == 3);

    ByteReader be{data};
    CHECK(be.u16be() == 0x0102);
    CHECK(be.u24be() == 0x030405);
    CHECK(be.u32be() == 0x06070809);
    CHECK(be.empty());

    ByteReader le{data};
    CHECK(le.u24le() == 0x030201);
    CHECK(le.u32le() == 0x07060504);

    ByteReader le64{data};
    CHECK(le64.u64le() == 0x0807060504030201ULL);
    CHECK(le64.remaining() == 1);
}

TEST_CASE("ByteReader failed reads do not consume", "[byte_reader]") {
    ByteReader r{std::span{data}.first(3)};
    CHECK_FALSE(r.u32le().has_value());
    CHECK(r.offset() == 0);
    CHECK_FALSE(r.bytes(4).has_value());
    CHECK_FALSE(r.array<4>().has_value());
    CHECK_FALSE(r.sub(4).has_value());
    CHECK_FALSE(r.skip(4));
    CHECK(r.remaining() == 3);
    CHECK(r.u24le() == 0x030201);
    CHECK_FALSE(r.u8().has_value());
    CHECK_FALSE(r.peek_u8().has_value());
}

TEST_CASE("ByteReader bytes, array, rest and sub", "[byte_reader]") {
    ByteReader r{data};
    CHECK(r.peek_u8() == 0x01);
    CHECK(r.offset() == 0);

    const auto two = r.bytes(2);
    REQUIRE(two.has_value());
    CHECK(two->size() == 2);
    CHECK((*two)[1] == 0x02);

    const auto oui = r.array<3>();
    REQUIRE(oui.has_value());
    CHECK(*oui == std::array<std::uint8_t, 3>{0x03, 0x04, 0x05});

    auto sub = r.sub(2);
    REQUIRE(sub.has_value());
    CHECK(sub->size() == 2);
    CHECK(sub->u16le() == 0x0706);
    CHECK(sub->empty());
    CHECK(r.offset() == 7);

    const auto rest = r.rest();
    CHECK(rest.size() == 2);
    CHECK(r.empty());
    CHECK(r.rest().empty());
    CHECK(r.bytes(0).has_value());
}

TEST_CASE("ByteReader on empty input", "[byte_reader]") {
    ByteReader r;
    CHECK(r.empty());
    CHECK_FALSE(r.u8().has_value());
    CHECK(r.rest().empty());
}

TEST_CASE("ByteReader is usable in constant expressions", "[byte_reader]") {
    constexpr auto value = [] {
        ByteReader r{data};
        r.skip(1);
        return *r.u16le();
    }();
    STATIC_CHECK(value == 0x0302);
}
