// SPDX-License-Identifier: MIT
// Channel numbering: IEEE Std 802.11-2020 Annex E (channel starting frequencies 2407 MHz,
// 5000 MHz, 5950 MHz, 56160 MHz; channel 14 at 2484 MHz; 6 GHz channel 2 at 5935 MHz).

#include <wifi_analyze/channel.hpp>

namespace wifi_analyze {

std::optional<ChannelInfo> channel_from_frequency(std::uint32_t mhz) noexcept {
    if (mhz == 2484) {
        return ChannelInfo{.band = Band::ghz_2_4, .channel = 14};
    }
    if (mhz >= 2412 && mhz <= 2472 && (mhz - 2407) % 5 == 0) {
        return ChannelInfo{.band = Band::ghz_2_4,
                           .channel = static_cast<std::uint16_t>((mhz - 2407) / 5)};
    }
    if (mhz == 5935) {
        return ChannelInfo{.band = Band::ghz_6, .channel = 2};
    }
    if (mhz >= 5955 && mhz <= 7115 && (mhz - 5950) % 5 == 0) {
        return ChannelInfo{.band = Band::ghz_6,
                           .channel = static_cast<std::uint16_t>((mhz - 5950) / 5)};
    }
    if (mhz >= 4910 && mhz <= 5895 && mhz % 5 == 0) {
        // 4.9 GHz channels (e.g. Japan) use the 4000 MHz starting frequency.
        if (mhz < 5000) {
            return ChannelInfo{.band = Band::ghz_5,
                               .channel = static_cast<std::uint16_t>((mhz - 4000) / 5)};
        }
        return ChannelInfo{.band = Band::ghz_5,
                           .channel = static_cast<std::uint16_t>((mhz - 5000) / 5)};
    }
    if (mhz >= 58320 && mhz <= 70200 && (mhz - 56160) % 2160 == 0) {
        return ChannelInfo{.band = Band::ghz_60,
                           .channel = static_cast<std::uint16_t>((mhz - 56160) / 2160)};
    }
    return std::nullopt;
}

std::optional<std::uint32_t> frequency_from_channel(Band band, std::uint16_t channel) noexcept {
    switch (band) {
    case Band::ghz_2_4:
        if (channel == 14) {
            return 2484;
        }
        if (channel >= 1 && channel <= 13) {
            return 2407U + (5U * channel);
        }
        return std::nullopt;
    case Band::ghz_5:
        if (channel >= 1 && channel <= 196) {
            return 5000U + (5U * channel);
        }
        return std::nullopt;
    case Band::ghz_6:
        if (channel == 2) {
            return 5935;
        }
        if (channel >= 1 && channel <= 233) {
            return 5950U + (5U * channel);
        }
        return std::nullopt;
    case Band::ghz_60:
        if (channel >= 1 && channel <= 6) {
            return 56160U + (2160U * channel);
        }
        return std::nullopt;
    case Band::unknown:
        break;
    }
    return std::nullopt;
}

Band band_from_operating_class(std::uint8_t op) noexcept {
    if (op >= 81 && op <= 84) {
        return Band::ghz_2_4;
    }
    if (op >= 115 && op <= 130) {
        return Band::ghz_5;
    }
    if (op >= 131 && op <= 137) {
        return Band::ghz_6;
    }
    if (op >= 180 && op <= 185) {
        return Band::ghz_60;
    }
    return Band::unknown;
}

std::string_view band_name(Band band) noexcept {
    switch (band) {
    case Band::ghz_2_4:
        return "2.4 GHz";
    case Band::ghz_5:
        return "5 GHz";
    case Band::ghz_6:
        return "6 GHz";
    case Band::ghz_60:
        return "60 GHz";
    case Band::unknown:
        break;
    }
    return {};
}

} // namespace wifi_analyze
