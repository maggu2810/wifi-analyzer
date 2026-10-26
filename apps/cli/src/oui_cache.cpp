// SPDX-License-Identifier: MIT
#include "oui_cache.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include <wifi_analyze/i18n.hpp>
#include <wifi_analyze/version.hpp>

#ifdef WIFI_CLI_WITH_CURL
#include <curl/curl.h>
#endif

namespace wifi_analyze_cli {

std::filesystem::path oui_cache_path() {
    std::filesystem::path base;
    if (const char* xdg = std::getenv("XDG_CACHE_HOME"); xdg != nullptr && *xdg != '\0') {
        base = xdg;
    } else if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        base = std::filesystem::path{home} / ".cache";
    } else {
        base = std::filesystem::temp_directory_path();
    }
    return base / "wifi-analyze" / "oui.csv";
}

std::optional<wifi_analyze::OuiDatabase> load_oui_cache() {
    std::ifstream in{oui_cache_path(), std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    auto db = wifi_analyze::OuiDatabase::parse_ieee_csv(ss.str());
    if (!db) {
        return std::nullopt;
    }
    return std::move(*db);
}

std::expected<std::size_t, std::string> store_oui_csv(const std::string& csv) {
    const auto db = wifi_analyze::OuiDatabase::parse_ieee_csv(csv);
    if (!db) {
        return std::unexpected(std::string{wifi_analyze::Localizer{}.text(db.error().message)});
    }
    const auto path = oui_cache_path();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return std::unexpected("cannot create " + path.parent_path().string() + ": " +
                               ec.message());
    }
    auto tmp = path;
    tmp += ".tmp";
    {
        std::ofstream out{tmp, std::ios::binary | std::ios::trunc};
        out << csv;
        if (!out) {
            return std::unexpected("cannot write " + tmp.string());
        }
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        return std::unexpected("cannot replace " + path.string() + ": " + ec.message());
    }
    return db->size();
}

bool oui_download_supported() noexcept {
#ifdef WIFI_CLI_WITH_CURL
    return true;
#else
    return false;
#endif
}

#ifdef WIFI_CLI_WITH_CURL
namespace {

std::size_t append(char* data, std::size_t size, std::size_t count, void* user) {
    static_cast<std::string*>(user)->append(data, size * count);
    return size * count;
}

} // namespace

std::expected<std::string, std::string> download(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        return std::unexpected("cannot initialize libcurl");
    }
    std::string body;
    const auto agent = "wifi-analyze-cli/" + std::string{wifi_analyze::version()};
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, agent.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    const auto rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        return std::unexpected(std::string{"download failed: "} + curl_easy_strerror(rc));
    }
    return body;
}
#else
std::expected<std::string, std::string> download(const std::string&) {
    return std::unexpected("this build has no download support (libcurl); use 'oui import FILE'");
}
#endif

} // namespace wifi_analyze_cli
