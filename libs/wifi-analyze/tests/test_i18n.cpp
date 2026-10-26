// SPDX-License-Identifier: MIT
#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <string>

#include <wifi_analyze/i18n.hpp>

using namespace wifi_analyze;

TEST_CASE("English is the default and first locale", "[i18n]") {
    CHECK(Localizer{}.locale() == "en");
    REQUIRE_FALSE(available_locales().empty());
    CHECK(available_locales().front() == "en");
}

TEST_CASE("every message has a key and an English text", "[i18n]") {
    const Localizer en;
    for (std::size_t i = 0; i < message_count; ++i) {
        const auto id = static_cast<MessageId>(i);
        INFO("message index " << i);
        CHECK_FALSE(message_key(id).empty());
        CHECK_FALSE(en.text(id).empty());
        CHECK(message_id_from_key(message_key(id)) == id);
    }
    CHECK_FALSE(message_id_from_key("does.not.exist").has_value());
    CHECK(message_key(MessageId::tlv_truncated) == "tlv_truncated");
}

TEST_CASE("locale selection normalizes and falls back", "[i18n]") {
    CHECK(localizer("de").locale() == "de");
    CHECK(localizer("de_DE").locale() == "de");
    CHECK(localizer("de-AT").locale() == "de");
    CHECK(localizer("DE_de.UTF-8@euro").locale() == "de");
    CHECK(localizer("").locale() == "en");
    CHECK(localizer("C").locale() == "en");
    CHECK(localizer("POSIX").locale() == "en");
    CHECK(localizer("xx_YY").locale() == "en");
    CHECK(localizer("a-very-long-and-bogus-locale-name").locale() == "en");
}

TEST_CASE("translated and formatted messages", "[i18n]") {
    const std::array<std::string, 4> args{"48", "12", "20", "3"};
    CHECK(Localizer{}.format(MessageId::tlv_truncated, args) ==
          "Element 48 at offset 12 declares 20 octets but only 3 remain");
    CHECK(localizer("de").format(MessageId::tlv_truncated, args) ==
          "Element 48 an Offset 12 gibt 20 Oktette an, aber nur 3 sind vorhanden");
}

TEST_CASE("format_message placeholder handling", "[i18n]") {
    const std::array<std::string, 2> args{"a", "b"};
    CHECK(format_message("{1}{0}{1}", args) == "bab");
    CHECK(format_message("{{0}} {0}", args) == "{0} a");
    CHECK(format_message("{2} missing", args) == "{2} missing");
    CHECK(format_message("{x} {} {", args) == "{x} {} {");
    CHECK(format_message("no placeholders", {}) == "no placeholders");
    CHECK(format_message("}", {}) == "}");
}
