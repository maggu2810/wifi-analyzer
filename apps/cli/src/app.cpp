// SPDX-License-Identifier: MIT
#include "app.hpp"

#include <CLI/CLI.hpp>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <sys/ioctl.h>
#include <unistd.h>

#include <wifi_analyze/capture.hpp>
#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/json.hpp>
#include <wifi_analyze/version.hpp>

#include "input.hpp"
#include "oui_cache.hpp"
#include "render.hpp"

namespace wifi_analyze_cli {
namespace {

namespace wa = wifi_analyze;

struct GlobalOptions {
    std::string lang;
    std::string color{"auto"};
    bool no_oui_database{false};
};

struct InputOptions {
    std::string input;
    std::string input_format{"auto"};
    std::uint32_t frequency{0};
    std::string bss;
    std::string format{"text"};
    bool anonymize{false};
    std::uint64_t salt{0};
};

std::string read_all(std::istream& in) {
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

/// INPUT: "-"/empty = stdin, an existing file path, otherwise literal text.
std::expected<std::string, std::string> load_input(const std::string& input, std::istream& in) {
    if (input.empty() || input == "-") {
        return read_all(in);
    }
    std::error_code ec;
    if (std::filesystem::is_regular_file(input, ec)) {
        std::ifstream file{input, std::ios::binary};
        if (!file) {
            return std::unexpected("cannot read " + input);
        }
        return read_all(file);
    }
    return input;
}

std::string locale_from_environment() {
    for (const char* name : {"LC_ALL", "LC_MESSAGES", "LANG"}) {
        if (const char* v = std::getenv(name); v != nullptr && *v != '\0') {
            return v;
        }
    }
    return "en";
}

bool use_color(const std::string& mode, const std::ostream& out) {
    if (mode == "always") {
        return true;
    }
    if (mode == "never" || &out != &std::cout) {
        return false;
    }
    const char* term = std::getenv("TERM");
    return isatty(STDOUT_FILENO) != 0 && std::getenv("NO_COLOR") == nullptr &&
           (term == nullptr || std::string_view{term} != "dumb");
}

unsigned terminal_width(const std::ostream& out) {
    if (&out == &std::cout && isatty(STDOUT_FILENO) != 0) {
        winsize ws{};
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20) {
            return ws.ws_col;
        }
    }
    if (const char* columns = std::getenv("COLUMNS"); columns != nullptr) {
        unsigned value = 0;
        const std::string_view text{columns};
        if (std::from_chars(text.data(), text.data() + text.size(), value).ec == std::errc{}) {
            return std::max(40U, value);
        }
    }
    return 100;
}

/// Shared state for one invocation.
struct Session {
    std::ostream& out;
    std::ostream& err;
    wa::Localizer localizer;
    std::optional<wa::OuiDatabase> oui;
    RenderOptions render;
};

DecodedBss decode_bss(const InputBss& input, const Session& session, std::uint32_t frequency) {
    wa::DecodeContext ctx;
    if (input.frequency_mhz) {
        ctx.frequency_mhz = input.frequency_mhz;
    } else if (frequency != 0) {
        ctx.frequency_mhz = frequency;
    }
    ctx.privacy = input.privacy;
    ctx.oui_database = session.oui ? &*session.oui : nullptr;
    DecodedBss bss;
    bss.input = &input;
    bss.ies = wa::decode(input.ies, ctx);
    bss.summary = wa::summarize(bss.ies, ctx);
    if (input.beacon_ies) {
        bss.beacon_ies = wa::decode(*input.beacon_ies, ctx);
    }
    return bss;
}

void anonymize(std::vector<InputBss>& list, std::uint64_t salt) {
    const wa::AnonymizeOptions options{.salt = salt, .keep_oui = true};
    for (auto& b : list) {
        b.ies = wa::anonymize_ies(b.ies, options);
        if (b.beacon_ies) {
            b.beacon_ies = wa::anonymize_ies(*b.beacon_ies, options);
        }
        if (b.bssid) {
            b.bssid = wa::anonymize_mac(*b.bssid, options);
        }
        if (b.ssid) {
            const auto anon = wa::anonymize_ssid(
                std::span{reinterpret_cast<const std::uint8_t*>(b.ssid->data()), b.ssid->size()},
                options);
            b.ssid = std::string(anon.begin(), anon.end());
        }
    }
}

nlohmann::json bss_json(const DecodedBss& bss, const Session& session, const wa::JsonOptions& opt) {
    nlohmann::json j;
    const auto& in = *bss.input;
    j["bssid"] = in.bssid ? nlohmann::json(format_mac(*in.bssid)) : nlohmann::json(nullptr);
    j["ssid"] = in.ssid ? nlohmann::json(*in.ssid) : nlohmann::json(nullptr);
    j["frequency_mhz"] =
        in.frequency_mhz ? nlohmann::json(*in.frequency_mhz) : nlohmann::json(nullptr);
    j["signal_dbm"] = in.signal_dbm ? nlohmann::json(*in.signal_dbm) : nlohmann::json(nullptr);
    j["age_ms"] = in.age_ms ? nlohmann::json(*in.age_ms) : nlohmann::json(nullptr);
    j["ies"] = nlohmann::json::parse(wa::to_json(bss.ies, bss.summary, session.localizer, opt));
    if (bss.beacon_ies) {
        const auto beacon_summary = wa::summarize(*bss.beacon_ies);
        j["beacon_ies"] = nlohmann::json::parse(
            wa::to_json(*bss.beacon_ies, beacon_summary, session.localizer, opt));
    } else {
        j["beacon_ies"] = nullptr;
    }
    return j;
}

void write_result_json(const std::vector<const DecodedBss*>& list, const Session& session,
                       const wa::JsonOptions& opt) {
    nlohmann::json doc;
    doc["schema"] = "wifi-analyze.cli-result";
    doc["schema_version"] = 1;
    doc["results"] = nlohmann::json::array();
    for (const auto* bss : list) {
        doc["results"].push_back(bss_json(*bss, session, opt));
    }
    session.out << doc.dump(2) << '\n';
}

std::string utc_now() {
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    return std::format("{:%FT%TZ}", now);
}

void write_capture(const std::vector<InputBss>& list, const Session& session) {
    nlohmann::json doc;
    const auto created = utc_now();
    doc["format"] = wa::capture_format;
    doc["format_version"] = wa::capture_format_version;
    doc["created"] = created;
    doc["source"] = {{"platform", "linux-cli"},
                     {"app", "wifi-analyze-cli"},
                     {"app_version", std::string{wa::version()}}};
    nlohmann::json bss_list = nlohmann::json::array();
    for (const auto& b : list) {
        nlohmann::json j;
        j["bssid"] = b.bssid ? nlohmann::json(format_mac(*b.bssid)) : nlohmann::json(nullptr);
        j["ssid"] = b.ssid ? nlohmann::json(*b.ssid) : nlohmann::json(nullptr);
        j["freq_mhz"] =
            b.frequency_mhz ? nlohmann::json(*b.frequency_mhz) : nlohmann::json(nullptr);
        j["signal_dbm"] = b.signal_dbm ? nlohmann::json(*b.signal_dbm) : nlohmann::json(nullptr);
        j["age_ms"] = b.age_ms ? nlohmann::json(*b.age_ms) : nlohmann::json(nullptr);
        if (b.capabilities) {
            j["capabilities"] = *b.capabilities;
        }
        j["platform"] = {{"flags", b.flags}};
        j["ies"] = wa::to_hex(b.ies);
        j["beacon_ies"] =
            b.beacon_ies ? nlohmann::json(wa::to_hex(*b.beacon_ies)) : nlohmann::json(nullptr);
        bss_list.push_back(std::move(j));
    }
    doc["scans"] = nlohmann::json::array({{{"timestamp", created}, {"bss", std::move(bss_list)}}});
    session.out << doc.dump(2) << '\n';
}

/// Parses and optionally anonymizes the input; reports errors on `err`.
std::optional<std::vector<InputBss>> load_bss(const InputOptions& o, std::istream& in,
                                              Session& session) {
    const auto text = load_input(o.input, in);
    if (!text) {
        session.err << "error: " << text.error() << '\n';
        return std::nullopt;
    }
    const auto format = parse_input_format(o.input_format);
    if (!format) {
        session.err << "error: unknown input format '" << o.input_format << "'\n";
        return std::nullopt;
    }
    auto list = parse_input(*text, *format);
    if (!list) {
        session.err << "error: " << list.error().message << '\n';
        return std::nullopt;
    }
    if (!o.bss.empty()) {
        const auto wanted = parse_mac(o.bss);
        std::erase_if(*list, [&](const InputBss& b) { return !wanted || b.bssid != wanted; });
        if (list->empty()) {
            session.err << "error: BSS " << o.bss << " not found in input\n";
            return std::nullopt;
        }
    }
    if (o.anonymize) {
        anonymize(*list, o.salt != 0 ? o.salt : std::random_device{}());
    }
    return std::move(*list);
}

// --- list: sorting and filtering -------------------------------------------------------

bool matches_filter(const DecodedBss& b, std::string_view key, std::string_view op,
                    std::string_view value) {
    const auto& s = b.summary;
    const auto lower = [](std::string text) {
        std::ranges::transform(text, text.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return text;
    };
    if (key == "band") {
        const auto name = wa::band_name(s.phy.band);
        return name.substr(0, name.find(' ')) == value;
    }
    if (key == "security") {
        return wa::security_type_key(s.security.type).contains(value);
    }
    if (key == "ssid") {
        return op == "~=" ? lower(s.ssid).contains(lower(std::string{value})) : s.ssid == value;
    }
    if (key == "gen") {
        return std::to_string(s.phy.generation) == value;
    }
    if (key == "channel") {
        return s.phy.primary_channel && std::to_string(*s.phy.primary_channel) == value;
    }
    if (key == "min-signal") {
        try {
            return b.input->signal_dbm && *b.input->signal_dbm >= std::stoi(std::string{value});
        } catch (const std::exception&) {
            return false;
        }
    }
    return true;
}

std::expected<std::vector<const DecodedBss*>, std::string>
filter_and_sort(const std::vector<DecodedBss>& all, const std::string& filter,
                const std::string& sort, bool reverse) {
    std::vector<const DecodedBss*> rows;
    for (const auto& b : all) {
        rows.push_back(&b);
    }
    std::stringstream ss{filter};
    std::string term;
    while (std::getline(ss, term, ',')) {
        if (term.empty()) {
            continue;
        }
        const auto tilde = term.find("~=");
        const auto eq = term.find('=');
        if (eq == std::string::npos) {
            return std::unexpected("invalid filter term '" + term + "' (expected key=value)");
        }
        const auto key = term.substr(0, tilde != std::string::npos ? tilde : eq);
        const auto op = tilde != std::string::npos ? std::string{"~="} : std::string{"="};
        const auto value = term.substr(eq + 1);
        static const std::vector<std::string> keys{"band", "security", "ssid",
                                                   "gen",  "channel",  "min-signal"};
        if (std::ranges::find(keys, key) == keys.end()) {
            return std::unexpected("unknown filter key '" + key + "'");
        }
        std::erase_if(rows,
                      [&](const DecodedBss* b) { return !matches_filter(*b, key, op, value); });
    }

    const auto signal = [](const DecodedBss* b) {
        return b->input->signal_dbm.value_or(-1000);
    };
    const auto channel = [](const DecodedBss* b) {
        return b->summary.phy.primary_frequency_mhz.value_or(0);
    };
    std::function<bool(const DecodedBss*, const DecodedBss*)> less;
    if (sort == "signal") {
        less = [&](auto* a, auto* b) {
            return signal(a) > signal(b);
        }; // strongest first
    } else if (sort == "ssid") {
        less = [](auto* a, auto* b) {
            return a->summary.ssid < b->summary.ssid;
        };
    } else if (sort == "bssid") {
        less = [](auto* a, auto* b) {
            return a->input->bssid < b->input->bssid;
        };
    } else if (sort == "channel") {
        less = [&](auto* a, auto* b) {
            return channel(a) < channel(b);
        };
    } else if (sort == "band") {
        less = [](auto* a, auto* b) {
            return a->summary.phy.band < b->summary.phy.band;
        };
    } else if (sort == "security") {
        less = [](auto* a, auto* b) {
            return a->summary.security.type > b->summary.security.type;
        };
    } else if (sort == "generation") {
        less = [](auto* a, auto* b) {
            return a->summary.phy.generation > b->summary.phy.generation;
        };
    } else {
        return std::unexpected("unknown sort key '" + sort + "'");
    }
    std::ranges::stable_sort(rows, less);
    if (reverse) {
        std::ranges::reverse(rows);
    }
    return rows;
}

// --- commands ----------------------------------------------------------------------------

int cmd_decode(const InputOptions& o, std::istream& in, Session& session) {
    auto list = load_bss(o, in, session);
    if (!list) {
        return exit_input;
    }
    if (o.format == "capture") {
        write_capture(*list, session);
        return exit_ok;
    }
    std::vector<DecodedBss> decoded;
    decoded.reserve(list->size());
    for (const auto& b : *list) {
        decoded.push_back(decode_bss(b, session, o.frequency));
    }
    if (o.format == "json") {
        std::vector<const DecodedBss*> ptrs;
        for (const auto& d : decoded) {
            ptrs.push_back(&d);
        }
        write_result_json(ptrs, session, {.include_detail = session.render.verbose});
        return exit_ok;
    }
    TextRenderer renderer{session.out, session.render, session.localizer};
    for (const auto& d : decoded) {
        renderer.bss(d);
    }
    return exit_ok;
}

int cmd_list(const InputOptions& o, const std::string& filter, const std::string& sort,
             bool reverse, std::istream& in, Session& session) {
    auto list = load_bss(o, in, session);
    if (!list) {
        return exit_input;
    }
    std::vector<DecodedBss> decoded;
    decoded.reserve(list->size());
    for (const auto& b : *list) {
        decoded.push_back(decode_bss(b, session, o.frequency));
    }
    const auto rows = filter_and_sort(decoded, filter, sort, reverse);
    if (!rows) {
        session.err << "error: " << rows.error() << '\n';
        return exit_usage;
    }
    if (o.format == "json") {
        write_result_json(*rows, session, {.include_payload = false, .include_tree = false});
    } else if (o.format == "capture") {
        std::vector<InputBss> selected;
        for (const auto* r : *rows) {
            selected.push_back(*r->input);
        }
        write_capture(selected, session);
    } else {
        TextRenderer{session.out, session.render, session.localizer}.table(*rows);
    }
    return exit_ok;
}

int cmd_interactive(std::istream& in, Session& session) {
    const bool tty = &in == &std::cin && isatty(STDIN_FILENO) != 0;
    if (tty) {
        session.out << "wifi-analyze-cli " << wa::version()
                    << " – paste an IE hex string (one line) or a wpa_cli BSS block followed by an "
                       "empty line. Ctrl-D quits.\n";
    }
    TextRenderer renderer{session.out, session.render, session.localizer};
    std::string block;
    std::string line;
    const auto process = [&] {
        if (block.find_first_not_of(" \t\r\n") == std::string::npos) {
            block.clear();
            return;
        }
        const auto list = parse_input(block, InputFormat::auto_detect);
        block.clear();
        if (!list) {
            session.err << "error: " << list.error().message << '\n';
            return;
        }
        for (const auto& b : *list) {
            renderer.bss(decode_bss(b, session, 0));
        }
    };
    while (true) {
        if (tty) {
            session.out << (block.empty() ? "> " : ". ") << std::flush;
        }
        if (!std::getline(in, line)) {
            process();
            break;
        }
        const bool key_value = line.contains('=');
        if (block.empty() && !key_value && !line.empty()) {
            block = line; // single-line hex: decode immediately
            process();
            continue;
        }
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
            process();
            continue;
        }
        block += line;
        block += '\n';
    }
    return exit_ok;
}

int cmd_elements(const std::string& format, Session& session) {
    const auto infos = wa::known_elements();
    if (format == "json") {
        nlohmann::json list = nlohmann::json::array();
        for (const auto& i : infos) {
            nlohmann::json j{{"id", i.key.id},
                             {"type", i.type},
                             {"name", session.localizer.text(i.name)},
                             {"spec", i.spec_reference},
                             {"decoded", i.decoded}};
            if (i.key.ext_id) {
                j["ext_id"] = *i.key.ext_id;
            }
            if (i.key.oui) {
                j["oui"] = std::format("{:02x}:{:02x}:{:02x}", (*i.key.oui)[0], (*i.key.oui)[1],
                                       (*i.key.oui)[2]);
            }
            if (i.key.vendor_type) {
                j["vendor_type"] = *i.key.vendor_type;
            }
            list.push_back(std::move(j));
        }
        session.out << list.dump(2) << '\n';
        return exit_ok;
    }
    TextRenderer{session.out, session.render, session.localizer}.elements(infos);
    return exit_ok;
}

int cmd_oui(const std::string& action, const std::string& argument, Session& session) {
    const auto path = oui_cache_path();
    if (action == "status") {
        session.out << "cache:    " << path.string() << '\n';
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            session.out << "state:    not present (built-in vendor subset is used)\n";
        } else {
            const auto db = load_oui_cache();
            const auto time = std::filesystem::last_write_time(path, ec);
            session.out << "state:    " << (db ? "valid" : "invalid") << '\n';
            if (db) {
                session.out << "entries:  " << db->size() << '\n';
            }
            if (!ec) {
                const auto sys = std::chrono::clock_cast<std::chrono::system_clock>(time);
                session.out << std::format("modified: {:%F %T}\n",
                                           std::chrono::floor<std::chrono::seconds>(sys));
            }
        }
        session.out << "download: " << (oui_download_supported() ? "supported" : "not available")
                    << '\n';
        return exit_ok;
    }
    if (action == "clear") {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        if (ec) {
            session.err << "error: " << ec.message() << '\n';
            return exit_oui;
        }
        session.out << "removed " << path.string() << '\n';
        return exit_ok;
    }
    std::expected<std::string, std::string> csv;
    if (action == "import") {
        std::ifstream file{argument, std::ios::binary};
        if (!file) {
            session.err << "error: cannot read " << argument << '\n';
            return exit_oui;
        }
        csv = read_all(file);
    } else if (action == "update") {
        session.err << "downloading " << argument << " ...\n";
        csv = download(argument);
    } else {
        session.err << "error: unknown oui action '" << action << "'\n";
        return exit_usage;
    }
    if (!csv) {
        session.err << "error: " << csv.error() << '\n';
        return exit_oui;
    }
    const auto stored = store_oui_csv(*csv);
    if (!stored) {
        session.err << "error: " << stored.error() << '\n';
        return exit_oui;
    }
    session.out << "stored " << *stored << " vendor entries in " << path.string() << '\n';
    return exit_ok;
}

void add_input_options(CLI::App* cmd, InputOptions& o, bool with_input = true) {
    if (with_input) {
        cmd->add_option("input", o.input, "Hex string, file, or '-' for stdin (default: stdin)");
    }
    cmd->add_option("--input-format", o.input_format, "Input format")
        ->check(CLI::IsMember({"auto", "hex", "wpa-bss", "capture"}));
    cmd->add_option("--freq", o.frequency, "Frequency in MHz when the input has none");
    cmd->add_option("--bss", o.bss, "Only the BSS with this BSSID");
    cmd->add_flag("--anonymize", o.anonymize,
                  "Replace SSIDs, BSSIDs and device identifiers with pseudonyms");
    cmd->add_option("--anonymize-salt", o.salt, "Salt for reproducible pseudonyms")->group("");
}

} // namespace

int run(const std::vector<std::string>& args, std::istream& in, std::ostream& out,
        std::ostream& err) {
    CLI::App app{"Decode IEEE 802.11 Information Elements (IEs) and summarize WiFi networks",
                 "wifi-analyze-cli"};
    app.set_version_flag("--version", std::string{wa::version()});
    app.require_subcommand(1);
    app.fallthrough();

    GlobalOptions global;
    RenderOptions render;
    app.add_option("--lang", global.lang, "Language of decoded labels (default: from LANG)");
    app.add_option("--color", global.color, "Colored output")
        ->check(CLI::IsMember({"auto", "always", "never"}));
    app.add_flag("--no-oui-database", global.no_oui_database,
                 "Do not load the cached full vendor database");
    app.add_flag("-v,--verbose", render.verbose,
                 "Show detail fields, info diagnostics and byte ranges");
    app.add_flag("--raw", render.raw, "Print the payload hex of every element");
    app.add_flag("--hexdump", render.hexdump, "Print a hex dump of every element");
    app.add_flag("--summary", render.summary_only, "Only print the summary of each BSS");

    InputOptions decode_options;
    auto* decode = app.add_subcommand("decode", "Decode IEs (hex, wpa_cli BSS output or capture)");
    add_input_options(decode, decode_options);
    decode->add_option("--format", decode_options.format, "Output format")
        ->check(CLI::IsMember({"text", "json", "capture"}));

    InputOptions list_options;
    std::string filter;
    std::string sort{"signal"};
    bool reverse = false;
    auto* list = app.add_subcommand("list", "Table of all BSSs of a multi-BSS input");
    add_input_options(list, list_options);
    list->add_option("--format", list_options.format, "Output format")
        ->check(CLI::IsMember({"text", "json", "capture"}));
    list->add_option("--sort", sort, "Sort key")
        ->check(CLI::IsMember(
            {"signal", "ssid", "bssid", "channel", "band", "security", "generation"}));
    list->add_flag("--reverse", reverse, "Reverse the sort order");
    list->add_option("--filter", filter,
                     "Comma separated: band=2.4|5|6, security=<part of type>, ssid=<name>, "
                     "ssid~=<substring>, gen=4..7, channel=<n>, min-signal=<dBm>");

    auto* interactive = app.add_subcommand("interactive", "Paste-and-decode loop");

    std::string elements_format{"text"};
    auto* elements = app.add_subcommand("elements", "List all known element types");
    elements->add_option("--format", elements_format, "Output format")
        ->check(CLI::IsMember({"text", "json"}));

    auto* oui = app.add_subcommand("oui", "Manage the optional full vendor (OUI) database");
    oui->require_subcommand(1);
    oui->add_subcommand("status", "Show cache location and state");
    std::string oui_url{default_oui_url};
    auto* oui_update = oui->add_subcommand("update", "Download the IEEE OUI registry");
    oui_update->add_option("--url", oui_url, "Source URL");
    std::string oui_file;
    auto* oui_import = oui->add_subcommand("import", "Import a downloaded oui.csv file");
    oui_import->add_option("file", oui_file, "IEEE oui.csv")->required();
    oui->add_subcommand("clear", "Remove the cached database");

    std::vector<std::string> reversed(args.rbegin(), args.rend());
    try {
        app.parse(reversed);
    } catch (const CLI::ParseError& e) {
        // Help and --version are reported as "success" parse errors; app.exit() prints them.
        return app.exit(e, out, err) == 0 ? exit_ok : exit_usage;
    }

    Session session{
        .out = out,
        .err = err,
        .localizer = wa::localizer(global.lang.empty() ? locale_from_environment() : global.lang),
        .oui = std::nullopt,
        .render = render};
    session.render.color = use_color(global.color, out);
    session.render.width = terminal_width(out);
    if (!global.no_oui_database) {
        session.oui = load_oui_cache();
    }

    if (decode->parsed()) {
        return cmd_decode(decode_options, in, session);
    }
    if (list->parsed()) {
        return cmd_list(list_options, filter, sort, reverse, in, session);
    }
    if (interactive->parsed()) {
        return cmd_interactive(in, session);
    }
    if (elements->parsed()) {
        return cmd_elements(elements_format, session);
    }
    if (oui->parsed()) {
        for (const auto* sub : oui->get_subcommands()) {
            const auto& name = sub->get_name();
            return cmd_oui(name, name == "update" ? oui_url : oui_file, session);
        }
    }
    return exit_usage;
}

} // namespace wifi_analyze_cli
