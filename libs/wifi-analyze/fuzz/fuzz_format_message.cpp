// SPDX-License-Identifier: MIT
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <wifi_analyze/i18n.hpp>

// Input: pattern, then up to three arguments, separated by NUL bytes.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view rest{reinterpret_cast<const char*>(data), size};
    std::array<std::string, 4> parts;
    std::size_t count = 0;
    while (count < parts.size()) {
        const auto nul = rest.find('\0');
        parts[count++] = std::string{rest.substr(0, nul)};
        if (nul == std::string_view::npos) {
            break;
        }
        rest.remove_prefix(nul + 1);
    }
    const std::span<const std::string> args{parts.data() + 1, count > 0 ? count - 1 : 0};
    static_cast<void>(wifi_analyze::format_message(parts[0], args));
    static_cast<void>(wifi_analyze::localizer(parts[0]).locale());
    static_cast<void>(wifi_analyze::message_id_from_key(parts[0]));
    return 0;
}
