// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>

#include "app.hpp"
#include "input.hpp"
#include "render.hpp"

using namespace wifi_analyze_cli;

namespace {

std::string testdata(const std::string& relative) {
    return std::string{WIFI_TESTDATA_DIR} + "/" + relative;
}

struct Result {
    int code;
    std::string out;
    std::string err;
};

Result cli(std::vector<std::string> args, const std::string& stdin_text = {}) {
    std::istringstream in{stdin_text};
    std::ostringstream out;
    std::ostringstream err;
    args.insert(args.begin(), {"--color", "never", "--no-oui-database"});
    const int code = run(args, in, out, err);
    return {code, out.str(), err.str()};
}

std::string read(const std::string& path) {
    std::ifstream f{path};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

TEST_CASE("input format detection", "[cli][input]") {
    CHECK(detect_format(" 0007486f6d65 ") == InputFormat::hex);
    CHECK(detect_format("bssid=00:11:22:33:44:55\nie=00\n") == InputFormat::wpa_bss);
    CHECK(detect_format("  {\"format\":1}") == InputFormat::capture);
    CHECK(parse_input_format("wpa-bss") == InputFormat::wpa_bss);
    CHECK_FALSE(parse_input_format("nope").has_value());
}

TEST_CASE("wpa_cli BSS dump parsing", "[cli][input]") {
    const auto list =
        parse_input(read(testdata("captures/wpa/bss-dump.txt")), InputFormat::auto_detect);
    REQUIRE(list.has_value());
    REQUIRE(list->size() == 4);
    const auto& first = (*list)[0];
    CHECK(format_mac(*first.bssid) == "aa:bb:cc:00:11:22");
    CHECK(first.frequency_mhz == 5180);
    CHECK(first.signal_dbm == -48);
    CHECK(first.age_ms == 3000);
    CHECK(first.capabilities == 0x0011);
    CHECK(first.privacy == true);
    CHECK(first.ssid == "HomeNet");
    CHECK(first.flags == "[WPA2-PSK+SAE-CCMP][ESS]");
    CHECK(first.beacon_ies.has_value());
    CHECK_FALSE(first.ies.empty());
    CHECK((*list)[3].privacy == false);
    CHECK_FALSE((*list)[1].beacon_ies.has_value());
}

TEST_CASE("wpa_cli block without ie is an error", "[cli][input]") {
    CHECK_FALSE(
        parse_input("bssid=00:11:22:33:44:55\nfreq=2412\n", InputFormat::wpa_bss).has_value());
    CHECK_FALSE(parse_input("bssid=00:11:22:33:44:55\nie=0g\n", InputFormat::wpa_bss).has_value());
}

TEST_CASE("decode text output", "[cli]") {
    const auto r = cli({"decode", testdata("captures/synthetic/wpa2-wpa3-5ghz-ax.hex")});
    CHECK(r.code == exit_ok);
    CHECK(r.out.contains("WPA2/WPA3-Personal"));
    CHECK(r.out.contains("Elements (17)"));
    CHECK(r.out.contains("[6] RSN (48)"));
    CHECK(r.err.empty());
}

TEST_CASE("decode from stdin and literal hex", "[cli]") {
    CHECK(cli({"decode", "--summary"}, "0004 74657374").out.contains("\"test\""));
    CHECK(cli({"decode", "0004 74657374", "--summary"}).out.contains("Open or WEP"));
}

TEST_CASE("RSN overriding is shown with both configurations", "[cli]") {
    const std::string ies = "0004 74657374 3014 0100 000fac04 0100 000fac04 0100 000fac02 8000 "
                            "dd18 506f9a29 0100 000fac04 0100 000fac04 0100 000fac08 c000";
    const auto list = cli({"list", ies});
    CHECK(list.code == exit_ok);
    CHECK(list.out.contains("WPA2-Personal (legacy clients) · WPA3-Personal (RSN overriding)"));
    CHECK(cli({"decode", ies, "--summary"}).out.contains("RSN Overriding"));
}

TEST_CASE("decode JSON output", "[cli]") {
    const auto r = cli({"decode", testdata("captures/wpa/bss-dump.txt"), "--format", "json"});
    REQUIRE(r.code == exit_ok);
    const auto doc = nlohmann::json::parse(r.out);
    CHECK(doc["schema"] == "wifi-analyze.cli-result");
    REQUIRE(doc["results"].size() == 4);
    CHECK(doc["results"][0]["bssid"] == "aa:bb:cc:00:11:22");
    CHECK(doc["results"][0]["ies"]["schema"] == "wifi-analyze.decoded");
    CHECK(doc["results"][0]["ies"]["summary"]["phy"]["channel_width_mhz"] == 80);
    CHECK(doc["results"][0]["beacon_ies"].is_object());
    CHECK(doc["results"][1]["ies"]["summary"]["device"]["manufacturer"] == "ACME Inc");
}

TEST_CASE("list sorting and filtering", "[cli]") {
    const auto dump = testdata("captures/wpa/bss-dump.txt");
    const auto by_signal = cli({"list", dump});
    REQUIRE(by_signal.code == exit_ok);
    CHECK(by_signal.out.find("HomeNet") < by_signal.out.find("Wifi7Lab"));
    CHECK(by_signal.out.find("Wifi7Lab") < by_signal.out.find("OldRouter"));

    const auto reversed = cli({"list", dump, "--reverse"});
    CHECK(reversed.out.find("CityFree") < reversed.out.find("HomeNet"));

    const auto by_ssid = cli({"list", dump, "--sort", "ssid"});
    CHECK(by_ssid.out.find("CityFree") < by_ssid.out.find("HomeNet"));

    const auto filtered = cli({"list", dump, "--filter", "band=2.4,ssid~=old"});
    CHECK(filtered.out.contains("OldRouter"));
    CHECK_FALSE(filtered.out.contains("CityFree"));
    CHECK_FALSE(filtered.out.contains("HomeNet"));

    CHECK_FALSE(cli({"list", dump, "--filter", "security=wpa3"}).out.contains("OldRouter"));
    CHECK(cli({"list", dump, "--filter", "bogus=1"}).code == exit_usage);
    CHECK(cli({"list", dump, "--sort", "bogus"}).code == exit_usage);
}

TEST_CASE("capture round trip and anonymization", "[cli]") {
    const auto dump = testdata("captures/wpa/bss-dump.txt");
    const auto capture = cli({"list", dump, "--format", "capture"});
    REQUIRE(capture.code == exit_ok);
    const auto parsed = parse_input(capture.out, InputFormat::auto_detect);
    REQUIRE(parsed.has_value());
    const auto original = parse_input(read(dump), InputFormat::auto_detect);
    REQUIRE(parsed->size() == original->size());
    // list sorts by signal; the strongest is the first block of the dump.
    CHECK((*parsed)[0].ies == (*original)[0].ies);
    CHECK((*parsed)[0].bssid == (*original)[0].bssid);
    CHECK((*parsed)[0].privacy == (*original)[0].privacy);

    const auto anon = cli({"decode", dump, "--format", "capture", "--anonymize"});
    REQUIRE(anon.code == exit_ok);
    CHECK_FALSE(anon.out.contains("HomeNet"));
    CHECK_FALSE(anon.out.contains("aa:bb:cc:00:11:22"));
    CHECK(anon.out.contains("ssid-"));
}

TEST_CASE("error handling and exit codes", "[cli]") {
    CHECK(cli({"decode", "zz"}).code == exit_input);
    CHECK(cli({"decode", "000"}).code == exit_input);
    CHECK(
        cli({"decode", testdata("captures/wpa/bss-dump.txt"), "--bss", "01:02:03:04:05:06"}).code ==
        exit_input);
    CHECK(cli({}).code == exit_usage);
    CHECK(cli({"nope"}).code == exit_usage);
    CHECK(cli({"--help"}).code == exit_ok);
}

TEST_CASE("interactive mode", "[cli]") {
    const auto hex = read(testdata("captures/synthetic/wpa2-wpa3-5ghz-ax.hex"));
    const auto wpa = read(testdata("captures/wpa/bss-dump.txt"));
    const auto r = cli({"interactive", "--summary"}, hex + "\n" + wpa + "\n" + "zz\n");
    CHECK(r.code == exit_ok);
    CHECK(r.out.contains("HomeNet"));
    CHECK(r.out.contains("CityFree"));
    CHECK(r.err.contains("Invalid character"));
}

TEST_CASE("elements listing", "[cli]") {
    const auto r = cli({"elements", "--format", "json"});
    REQUIRE(r.code == exit_ok);
    const auto list = nlohmann::json::parse(r.out);
    CHECK(list.size() > 80);
}

TEST_CASE("OUI cache import, status and clear", "[cli]") {
    const auto dir = std::filesystem::temp_directory_path() / "wifi-analyze-cli-test-xdg";
    std::filesystem::remove_all(dir);
    ::setenv("XDG_CACHE_HOME", dir.c_str(), 1);
    const auto csv = dir / "input.csv";
    std::filesystem::create_directories(dir);
    std::ofstream{csv} << "Registry,Assignment,Organization Name,Organization Address\n"
                          "MA-L,AABBCC,Test Vendor,Somewhere\n";

    CHECK(cli({"oui", "import", (dir / "missing.csv").string()}).code == exit_oui);
    const auto imported = cli({"oui", "import", csv.string()});
    CHECK(imported.code == exit_ok);
    CHECK(imported.out.contains("stored 1 vendor entries"));
    CHECK(cli({"oui", "status"}).out.contains("entries:  1"));

    // The cache is used for decoding (vendor element with OUI AA:BB:CC).
    std::istringstream in{"dd04aabbcc01"};
    std::ostringstream out;
    std::ostringstream err;
    CHECK(run({"--color", "never", "decode", "--summary"}, in, out, err) == exit_ok);
    CHECK(out.str().contains("Test Vendor"));

    CHECK(cli({"oui", "clear"}).code == exit_ok);
    CHECK(cli({"oui", "status"}).out.contains("not present"));
    ::unsetenv("XDG_CACHE_HOME");
    std::filesystem::remove_all(dir);
}

TEST_CASE("signal levels and display width", "[cli]") {
    CHECK(signal_level(-40) == 4);
    CHECK(signal_level(-60) == 3);
    CHECK(signal_level(-70) == 2);
    CHECK(signal_level(-80) == 1);
    CHECK(signal_level(-95) == 0);
    CHECK(display_width("äöü") == 3);
}
