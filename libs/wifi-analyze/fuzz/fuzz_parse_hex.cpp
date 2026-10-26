// SPDX-License-Identifier: MIT
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/i18n.hpp>

// parse_hex must never crash; successful parses must round-trip through to_hex, and
// diagnostics must be renderable.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    const auto result = wifi_analyze::parse_hex(text);
    if (result) {
        const auto again = wifi_analyze::parse_hex(wifi_analyze::to_hex(*result));
        if (!again || *again != *result) {
            std::abort();
        }
    } else {
        const auto message =
            wifi_analyze::Localizer{}.format(result.error().message, result.error().args);
        if (message.empty()) {
            std::abort();
        }
    }
    return 0;
}
