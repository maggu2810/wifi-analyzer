// SPDX-License-Identifier: MIT
// Thin JNI bridge: bytes in, JSON (schema wifi-analyze.decoded) out. No decoding logic here.

#include <jni.h>

#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include <wifi_analyze/capture.hpp>
#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/json.hpp>
#include <wifi_analyze/oui.hpp>
#include <wifi_analyze/summary.hpp>
#include <wifi_analyze/version.hpp>

namespace {

namespace wa = wifi_analyze;

// Optional full vendor database, replaced atomically; decoders hold a reference while running.
std::mutex oui_mutex;
std::shared_ptr<const wa::OuiDatabase> oui_database;

std::shared_ptr<const wa::OuiDatabase> current_oui() {
    const std::lock_guard lock{oui_mutex};
    return oui_database;
}

std::vector<std::uint8_t> to_bytes(JNIEnv* env, jbyteArray array) {
    if (array == nullptr) {
        return {};
    }
    const auto size = static_cast<std::size_t>(env->GetArrayLength(array));
    std::vector<std::uint8_t> bytes(size);
    if (size > 0) {
        env->GetByteArrayRegion(array, 0, static_cast<jsize>(size),
                                reinterpret_cast<jbyte*>(bytes.data()));
    }
    return bytes;
}

jbyteArray to_java(JNIEnv* env, std::span<const std::uint8_t> bytes) {
    auto* array = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (array != nullptr && !bytes.empty()) {
        env->SetByteArrayRegion(array, 0, static_cast<jsize>(bytes.size()),
                                reinterpret_cast<const jbyte*>(bytes.data()));
    }
    return array;
}

std::string to_string(JNIEnv* env, jstring s) {
    if (s == nullptr) {
        return {};
    }
    const char* chars = env->GetStringUTFChars(s, nullptr);
    std::string result{chars != nullptr ? chars : ""};
    if (chars != nullptr) {
        env->ReleaseStringUTFChars(s, chars);
    }
    return result;
}

jstring to_java(JNIEnv* env, const std::string& s) {
    // JSON output is valid UTF-8; NewStringUTF expects modified UTF-8, which differs only for
    // NUL and supplementary characters. Use a UTF-16 conversion to be safe.
    std::u16string utf16;
    utf16.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        char32_t cp = 0;
        std::size_t len = 1;
        if (c < 0x80) {
            cp = c;
        } else if ((c & 0xe0U) == 0xc0U && i + 1 < s.size()) {
            cp = ((c & 0x1fU) << 6U) | (static_cast<unsigned char>(s[i + 1]) & 0x3fU);
            len = 2;
        } else if ((c & 0xf0U) == 0xe0U && i + 2 < s.size()) {
            cp = ((c & 0x0fU) << 12U) | ((static_cast<unsigned char>(s[i + 1]) & 0x3fU) << 6U) |
                 (static_cast<unsigned char>(s[i + 2]) & 0x3fU);
            len = 3;
        } else if ((c & 0xf8U) == 0xf0U && i + 3 < s.size()) {
            cp = ((c & 0x07U) << 18U) | ((static_cast<unsigned char>(s[i + 1]) & 0x3fU) << 12U) |
                 ((static_cast<unsigned char>(s[i + 2]) & 0x3fU) << 6U) |
                 (static_cast<unsigned char>(s[i + 3]) & 0x3fU);
            len = 4;
        } else {
            cp = 0xfffd;
        }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            utf16.push_back(static_cast<char16_t>(0xd800U + (cp >> 10U)));
            utf16.push_back(static_cast<char16_t>(0xdc00U + (cp & 0x3ffU)));
        } else {
            utf16.push_back(static_cast<char16_t>(cp));
        }
        i += len;
    }
    return env->NewString(reinterpret_cast<const jchar*>(utf16.data()),
                          static_cast<jsize>(utf16.size()));
}

wa::DecodeContext context(jint frequency, jint privacy, const wa::OuiDatabase* oui) {
    wa::DecodeContext ctx;
    if (frequency > 0) {
        ctx.frequency_mhz = static_cast<std::uint32_t>(frequency);
    }
    if (privacy >= 0) {
        ctx.privacy = privacy != 0;
    }
    ctx.oui_database = oui;
    return ctx;
}

constexpr jint flag_tree = 1;
constexpr jint flag_payload = 2;
constexpr jint flag_detail = 4;

std::string decode_json(const std::vector<std::uint8_t>& ies, jint frequency, jint privacy,
                        const wa::Localizer& localizer, jint flags) {
    const auto oui = current_oui();
    const auto ctx = context(frequency, privacy, oui.get());
    const auto decoded = wa::decode(ies, ctx);
    const auto summary = wa::summarize(decoded, ctx);
    return wa::to_json(decoded, summary, localizer,
                       {.pretty = false,
                        .include_payload = (flags & flag_payload) != 0,
                        .include_tree = (flags & flag_tree) != 0,
                        .include_detail = (flags & flag_detail) != 0});
}

} // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeVersion(JNIEnv* env,
                                                                                  jobject) {
    return to_java(env, std::string{wa::version()});
}

JNIEXPORT jstring JNICALL Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeDecode(
    JNIEnv* env, jobject, jbyteArray ies, jint frequency, jint privacy, jstring locale, jint flags) {
    const auto localizer = wa::localizer(to_string(env, locale));
    return to_java(env, decode_json(to_bytes(env, ies), frequency, privacy, localizer, flags));
}

JNIEXPORT jstring JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeDecodeBatch(
    JNIEnv* env, jobject, jobjectArray ies_list, jintArray frequencies, jintArray privacy,
    jstring locale, jint flags) {
    const auto localizer = wa::localizer(to_string(env, locale));
    const auto count = env->GetArrayLength(ies_list);
    std::vector<jint> freq(static_cast<std::size_t>(count), 0);
    std::vector<jint> priv(static_cast<std::size_t>(count), -1);
    if (frequencies != nullptr && env->GetArrayLength(frequencies) == count && count > 0) {
        env->GetIntArrayRegion(frequencies, 0, count, freq.data());
    }
    if (privacy != nullptr && env->GetArrayLength(privacy) == count && count > 0) {
        env->GetIntArrayRegion(privacy, 0, count, priv.data());
    }
    std::string out = "[";
    for (jsize i = 0; i < count; ++i) {
        auto* element = static_cast<jbyteArray>(env->GetObjectArrayElement(ies_list, i));
        const auto bytes = to_bytes(env, element);
        env->DeleteLocalRef(element);
        if (i != 0) {
            out.push_back(',');
        }
        const auto idx = static_cast<std::size_t>(i);
        out += decode_json(bytes, freq[idx], priv[idx], localizer, flags);
    }
    out.push_back(']');
    return to_java(env, out);
}

JNIEXPORT jint JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeLoadOuiDatabase(
    JNIEnv* env, jobject, jbyteArray csv) {
    const auto bytes = to_bytes(env, csv);
    auto db = wa::OuiDatabase::parse_ieee_csv(
        std::string_view{reinterpret_cast<const char*>(bytes.data()), bytes.size()});
    if (!db) {
        return -1;
    }
    const auto size = static_cast<jint>(db->size());
    const std::lock_guard lock{oui_mutex};
    oui_database = std::make_shared<const wa::OuiDatabase>(std::move(*db));
    return size;
}

JNIEXPORT void JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeClearOuiDatabase(JNIEnv*,
                                                                                          jobject) {
    const std::lock_guard lock{oui_mutex};
    oui_database.reset();
}

JNIEXPORT jstring JNICALL Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeOuiName(
    JNIEnv* env, jobject, jint oui) {
    const wa::Oui key{static_cast<std::uint8_t>((oui >> 16) & 0xff),
                      static_cast<std::uint8_t>((oui >> 8) & 0xff),
                      static_cast<std::uint8_t>(oui & 0xff)};
    const auto db = current_oui();
    const auto name = wa::oui_name(key, db.get());
    return name ? to_java(env, std::string{*name}) : nullptr;
}

JNIEXPORT jbyteArray JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeAnonymizeIes(
    JNIEnv* env, jobject, jbyteArray ies, jlong salt) {
    const auto bytes = to_bytes(env, ies);
    return to_java(env, wa::anonymize_ies(bytes, {.salt = static_cast<std::uint64_t>(salt),
                                                  .keep_oui = true}));
}

JNIEXPORT jbyteArray JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeAnonymizeMac(
    JNIEnv* env, jobject, jbyteArray mac, jlong salt) {
    const auto bytes = to_bytes(env, mac);
    if (bytes.size() != 6) {
        return to_java(env, bytes);
    }
    wa::MacAddress m{};
    std::copy(bytes.begin(), bytes.end(), m.begin());
    const auto anon =
        wa::anonymize_mac(m, {.salt = static_cast<std::uint64_t>(salt), .keep_oui = true});
    return to_java(env, anon);
}

JNIEXPORT jbyteArray JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeAnonymizeSsid(
    JNIEnv* env, jobject, jbyteArray ssid, jlong salt) {
    const auto bytes = to_bytes(env, ssid);
    return to_java(env, wa::anonymize_ssid(bytes, {.salt = static_cast<std::uint64_t>(salt),
                                                   .keep_oui = true}));
}

JNIEXPORT jobjectArray JNICALL
Java_de_maggu2810_android_wifianalyzer_nativelib_WifiAnalyzeNative_nativeAvailableLocales(
    JNIEnv* env, jobject) {
    const auto locales = wa::available_locales();
    auto* string_class = env->FindClass("java/lang/String");
    auto* array = env->NewObjectArray(static_cast<jsize>(locales.size()), string_class, nullptr);
    for (std::size_t i = 0; i < locales.size(); ++i) {
        auto* s = to_java(env, std::string{locales[i]});
        env->SetObjectArrayElement(array, static_cast<jsize>(i), s);
        env->DeleteLocalRef(s);
    }
    return array;
}

} // extern "C"
