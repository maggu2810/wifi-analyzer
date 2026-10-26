// SPDX-License-Identifier: MIT
#include <cstddef>
#include <cstdint>
#include <span>

#include <wifi_analyze/capture.hpp>
#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/json.hpp>
#include <wifi_analyze/oui.hpp>
#include <wifi_analyze/summary.hpp>

// Full pipeline on arbitrary input: decode, summarize, overview, JSON in two locales.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    wifi_analyze::DecodeContext context;
    if (size > 0) {
        // Let the first byte select a band so frequency-dependent paths are exercised too.
        constexpr std::uint32_t frequencies[] = {0, 2437, 5180, 5975};
        if (const auto f = frequencies[data[0] % 4]; f != 0) {
            context.frequency_mhz = f;
        }
    }
    const auto ies = wifi_analyze::decode(std::span{data, size}, context);
    const auto summary = wifi_analyze::summarize(ies, context);
    static_cast<void>(wifi_analyze::describe(summary));
    static_cast<void>(wifi_analyze::to_json(ies, summary, wifi_analyze::Localizer{}));
    static_cast<void>(wifi_analyze::to_json(ies, summary, wifi_analyze::localizer("de"),
                                            {.pretty = true, .include_payload = false}));
    // Anonymization must produce a decodable stream as well.
    const auto anonymized =
        wifi_analyze::anonymize_ies(std::span{data, size}, {.salt = 1, .keep_oui = true});
    static_cast<void>(wifi_analyze::summarize(wifi_analyze::decode(anonymized, context), context));
    // The same bytes as OUI CSV text.
    static_cast<void>(wifi_analyze::OuiDatabase::parse_ieee_csv(
        std::string_view{reinterpret_cast<const char*>(data), size}));
    return 0;
}
