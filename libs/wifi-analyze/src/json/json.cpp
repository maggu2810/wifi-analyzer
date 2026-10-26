// SPDX-License-Identifier: MIT
#include <format>
#include <string>

#include <wifi_analyze/hex.hpp>
#include <wifi_analyze/json.hpp>

#include "core/decoder.hpp"
#include "ie/decoders.hpp"

namespace wifi_analyze {
namespace {

/// Minimal streaming JSON writer (output only). Callers emit well-formed sequences.
class JsonWriter {
public:
    explicit JsonWriter(bool pretty) : pretty_{pretty} {}

    void begin_object() { open('{'); }
    void end_object() { close('}'); }
    void begin_array() { open('['); }
    void end_array() { close(']'); }

    void key(std::string_view k) {
        separator();
        string_literal(k);
        out_ += pretty_ ? ": " : ":";
        after_key_ = true;
    }

    void value(std::string_view s) {
        separator();
        string_literal(s);
    }
    void value(const char* s) { value(std::string_view{s}); }
    void value(bool b) {
        separator();
        out_ += b ? "true" : "false";
    }
    void value(std::uint64_t v) {
        separator();
        out_ += std::to_string(v);
    }
    void value(std::int64_t v) {
        separator();
        out_ += std::to_string(v);
    }
    void value(double v) {
        separator();
        out_ += std::format("{:.10g}", v);
    }
    void null() {
        separator();
        out_ += "null";
    }

    template <class T>
        requires(!std::is_array_v<T>)
    void field(std::string_view k, const T& v) {
        key(k);
        value(v);
    }
    void field(std::string_view k, std::string_view v) {
        key(k);
        value(v);
    }
    template <class T>
    void optional_field(std::string_view k, const std::optional<T>& v) {
        key(k);
        if (v) {
            value(*v);
        } else {
            null();
        }
    }

    std::string take() { return std::move(out_); }

private:
    void open(char c) {
        separator();
        out_.push_back(c);
        first_ = true;
        ++depth_;
    }
    void close(char c) {
        --depth_;
        if (!first_) {
            newline();
        }
        out_.push_back(c);
        first_ = false;
    }
    void separator() {
        if (after_key_) {
            after_key_ = false;
            return;
        }
        if (!first_) {
            out_.push_back(',');
        }
        if (depth_ > 0) {
            newline();
        }
        first_ = false;
    }
    void newline() {
        if (pretty_) {
            out_.push_back('\n');
            out_.append(static_cast<std::size_t>(depth_) * 2, ' ');
        }
    }
    void string_literal(std::string_view s) {
        constexpr std::string_view digits = "0123456789abcdef";
        out_.push_back('"');
        for (const char ch : s) {
            const auto c = static_cast<unsigned char>(ch);
            switch (ch) {
            case '"':
                out_ += "\\\"";
                break;
            case '\\':
                out_ += "\\\\";
                break;
            case '\n':
                out_ += "\\n";
                break;
            case '\r':
                out_ += "\\r";
                break;
            case '\t':
                out_ += "\\t";
                break;
            default:
                if (c < 0x20) {
                    out_ += "\\u00";
                    out_.push_back(digits[c >> 4U]);
                    out_.push_back(digits[c & 0xfU]);
                } else {
                    out_.push_back(ch);
                }
            }
        }
        out_.push_back('"');
    }

    std::string out_;
    bool pretty_;
    bool first_{true};
    bool after_key_{false};
    int depth_{0};
};

std::string_view severity_key(Severity s) {
    switch (s) {
    case Severity::info:
        return "info";
    case Severity::warning:
        return "warning";
    case Severity::error:
        return "error";
    }
    return "error";
}

std::string_view status_key(DecodeStatus s) {
    switch (s) {
    case DecodeStatus::ok:
        return "ok";
    case DecodeStatus::unknown:
        return "unknown";
    case DecodeStatus::malformed:
        return "malformed";
    case DecodeStatus::truncated:
        return "truncated";
    }
    return "unknown";
}

std::string_view band_key(Band band) {
    switch (band) {
    case Band::ghz_2_4:
        return "2.4";
    case Band::ghz_5:
        return "5";
    case Band::ghz_6:
        return "6";
    case Band::ghz_60:
        return "60";
    case Band::unknown:
        break;
    }
    return {};
}

std::string_view pmf_key(Pmf p) {
    switch (p) {
    case Pmf::unknown:
        return "unknown";
    case Pmf::disabled:
        return "disabled";
    case Pmf::capable:
        return "capable";
    case Pmf::required:
        return "required";
    }
    return "unknown";
}

void range(JsonWriter& w, std::string_view k, const ByteRange& r) {
    w.key(k);
    w.begin_array();
    w.value(std::uint64_t{r.offset});
    w.value(std::uint64_t{r.length});
    w.end_array();
}

void diagnostics(JsonWriter& w, const std::vector<Diagnostic>& list, const Localizer& loc) {
    w.begin_array();
    for (const auto& d : list) {
        w.begin_object();
        w.field("severity", severity_key(d.severity));
        w.field("key", message_key(d.message));
        w.field("message", loc.format(d.message, d.args));
        w.key("args");
        w.begin_array();
        for (const auto& a : d.args) {
            w.value(a);
        }
        w.end_array();
        if (const auto& bytes = d.bytes) {
            range(w, "bytes", *bytes);
        }
        w.end_object();
    }
    w.end_array();
}

void node(JsonWriter& w, const TreeNode& n, const Localizer& loc, const JsonOptions& opt);

void children(JsonWriter& w, const std::vector<TreeNode>& list, const Localizer& loc,
              const JsonOptions& opt) {
    w.begin_array();
    for (const auto& c : list) {
        if (opt.include_detail || c.significance != Significance::detail) {
            node(w, c, loc, opt);
        }
    }
    w.end_array();
}

void node(JsonWriter& w, const TreeNode& n, const Localizer& loc, const JsonOptions& opt) {
    w.begin_object();
    w.field("key", message_key(n.label));
    w.field("label", loc.text(n.label));
    if (!std::holds_alternative<std::monostate>(n.value)) {
        w.field("text", format_value(n, loc));
        w.key("value");
        std::visit(
            [&](const auto& v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    w.null();
                } else if constexpr (std::is_same_v<T, std::vector<std::uint8_t>>) {
                    w.value(to_hex(v));
                } else if constexpr (std::is_same_v<T, EnumValue>) {
                    w.value(v.raw);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    w.value(std::string_view{v});
                } else {
                    w.value(v);
                }
            },
            n.value);
        if (const auto* e = std::get_if<EnumValue>(&n.value); e != nullptr && !e->name.empty()) {
            w.field("value_name", e->name.render(loc));
        }
    }
    if (n.unit != Unit::none) {
        w.field("unit", unit_symbol(n.unit));
    }
    if (n.bytes) {
        range(w, "bytes", *n.bytes);
    }
    if (n.bits) {
        w.key("bits");
        w.begin_array();
        w.value(std::uint64_t{n.bits->first});
        w.value(std::uint64_t{n.bits->count});
        w.end_array();
    }
    if (n.significance == Significance::detail) {
        w.field("significance", "detail");
    } else if (n.significance == Significance::warning) {
        w.field("significance", "warning");
    }
    if (!n.children.empty()) {
        w.key("children");
        children(w, n.children, loc, opt);
    }
    w.end_object();
}

void suite(JsonWriter& w, const Suite& s, bool akm, const Localizer& loc) {
    w.begin_object();
    w.field("suite", core::format_oui(s.oui) + ":" + std::to_string(s.type));
    w.field("name", (akm ? ie::akm_suite_name(s) : ie::cipher_suite_name(s)).render(loc));
    w.end_object();
}

void suites(JsonWriter& w, const std::vector<Suite>& akms, const std::vector<Suite>& pairwise,
            const std::optional<Suite>& group, const std::optional<Suite>& group_mgmt,
            const Localizer& loc) {
    w.key("akms");
    w.begin_array();
    for (const auto& a : akms) {
        suite(w, a, true, loc);
    }
    w.end_array();
    w.key("pairwise_ciphers");
    w.begin_array();
    for (const auto& c : pairwise) {
        suite(w, c, false, loc);
    }
    w.end_array();
    w.key("group_cipher");
    if (group) {
        suite(w, *group, false, loc);
    } else {
        w.null();
    }
    w.key("group_management_cipher");
    if (group_mgmt) {
        suite(w, *group_mgmt, false, loc);
    } else {
        w.null();
    }
}

void summary(JsonWriter& w, const BssSummary& s, const Localizer& loc) {
    w.begin_object();
    w.field("ssid", s.ssid);
    w.field("ssid_hex", to_hex(s.ssid_raw));
    w.field("ssid_present", s.ssid_present);
    w.field("hidden", s.hidden);

    w.key("security");
    w.begin_object();
    w.field("type", security_type_key(s.security.type));
    w.field("label", security_type_name(s.security.type).render(loc));
    w.field("pmf", pmf_key(s.security.pmf));
    w.field("pmf_label", pmf_name(s.security.pmf).render(loc));
    w.field("rsn", s.security.rsn);
    w.field("wpa1", s.security.wpa1);
    w.field("weak", s.security.weak);
    w.field("sae_h2e", s.security.sae_hash_to_element);
    w.field("sae_pk", s.security.sae_pk);
    w.field("display_label", security_label(s.security, loc));
    suites(w, s.security.akms, s.security.pairwise_ciphers, s.security.group_cipher,
           s.security.group_management_cipher, loc);
    w.key("overrides");
    w.begin_array();
    for (const auto& o : s.security.overrides) {
        w.begin_object();
        w.field("variant", std::uint64_t{o.variant});
        w.field("type", security_type_key(o.type));
        w.field("label", security_type_name(o.type).render(loc));
        w.field("pmf", pmf_key(o.pmf));
        w.field("pmf_label", pmf_name(o.pmf).render(loc));
        w.field("sae_h2e", o.sae_hash_to_element);
        w.field("sae_pk", o.sae_pk);
        suites(w, o.akms, o.pairwise_ciphers, o.group_cipher, o.group_management_cipher, loc);
        w.end_object();
    }
    w.end_array();
    w.end_object();

    const auto& p = s.phy;
    w.key("phy");
    w.begin_object();
    w.field("generation", std::uint64_t{p.generation});
    w.field("generation_label", generation_name(p));
    w.key("standards");
    w.begin_array();
    for (const auto st : p.standards) {
        w.value(phy_standard_name(st));
    }
    w.end_array();
    w.key("band");
    if (p.band == Band::unknown) {
        w.null();
    } else {
        w.value(band_key(p.band));
    }
    w.field("band_label", band_name(p.band));
    w.key("primary_channel");
    if (p.primary_channel) {
        w.value(std::uint64_t{*p.primary_channel});
    } else {
        w.null();
    }
    w.key("primary_frequency_mhz");
    if (p.primary_frequency_mhz) {
        w.value(std::uint64_t{*p.primary_frequency_mhz});
    } else {
        w.null();
    }
    w.field("channel_width_mhz", std::uint64_t{p.channel_width_mhz});
    w.field("eighty_plus_eighty", p.eighty_plus_eighty);
    w.key("center_frequencies_mhz");
    w.begin_array();
    for (const auto c : p.center_frequencies_mhz) {
        w.value(std::uint64_t{c});
    }
    w.end_array();
    w.key("punctured_subchannels");
    if (p.punctured_subchannels) {
        w.value(std::uint64_t{*p.punctured_subchannels});
    } else {
        w.null();
    }
    w.field("max_spatial_streams", std::uint64_t{p.max_spatial_streams});
    w.optional_field("max_rate_mbps", p.max_rate_mbps);
    w.optional_field("max_legacy_rate_mbps", p.max_legacy_rate_mbps);
    w.end_object();

    w.key("bss_load");
    if (s.bss_load) {
        w.begin_object();
        w.field("station_count", std::uint64_t{s.bss_load->station_count});
        w.field("channel_utilization", std::uint64_t{s.bss_load->channel_utilization});
        w.field("channel_utilization_percent", s.bss_load->channel_utilization * 100.0 / 255.0);
        w.field("available_admission_capacity",
                std::uint64_t{s.bss_load->available_admission_capacity});
        w.end_object();
    } else {
        w.null();
    }
    w.field("country", s.country);

    w.key("roaming");
    w.begin_object();
    w.field("k", s.roaming.k);
    w.field("v", s.roaming.v);
    w.field("r", s.roaming.r);
    w.field("ft_over_ds", s.roaming.ft_over_ds);
    w.end_object();

    w.field("wmm", s.wmm);
    w.field("uapsd", s.uapsd);
    w.key("bss_color");
    if (s.bss_color) {
        w.value(std::uint64_t{*s.bss_color});
    } else {
        w.null();
    }
    w.field("twt_responder", s.twt_responder);

    w.key("mlo");
    if (s.mlo) {
        w.begin_object();
        w.key("mld_mac");
        if (s.mlo->mld_mac) {
            w.value(core::format_mac(*s.mlo->mld_mac));
        } else {
            w.null();
        }
        w.key("link_id");
        if (s.mlo->link_id) {
            w.value(std::uint64_t{*s.mlo->link_id});
        } else {
            w.null();
        }
        w.key("max_simultaneous_links");
        if (s.mlo->max_simultaneous_links) {
            w.value(std::uint64_t{*s.mlo->max_simultaneous_links} + 1);
        } else {
            w.null();
        }
        w.field("reported_links", std::uint64_t{s.mlo->reported_links});
        w.end_object();
    } else {
        w.null();
    }

    w.key("neighbors");
    w.begin_array();
    for (const auto& n : s.neighbors) {
        w.begin_object();
        w.field("operating_class", std::uint64_t{n.operating_class});
        w.field("channel", std::uint64_t{n.channel});
        w.key("band");
        if (n.band == Band::unknown) {
            w.null();
        } else {
            w.value(band_key(n.band));
        }
        w.key("bssid");
        if (n.bssid) {
            w.value(core::format_mac(*n.bssid));
        } else {
            w.null();
        }
        w.field("same_ssid", n.same_ssid);
        w.field("co_located", n.co_located);
        w.end_object();
    }
    w.end_array();
    w.field("nontransmitted_bssids", std::uint64_t{s.nontransmitted_bssids});

    w.key("device");
    w.begin_object();
    w.field("manufacturer", s.device.manufacturer);
    w.field("model_name", s.device.model_name);
    w.field("model_number", s.device.model_number);
    w.field("device_name", s.device.device_name);
    w.field("serial_number", s.device.serial_number);
    w.end_object();

    w.key("access_network_type");
    if (s.access_network_type) {
        w.value(std::uint64_t{*s.access_network_type});
    } else {
        w.null();
    }
    w.optional_field("internet", s.internet);
    w.key("hotspot20_release");
    if (s.hotspot20_release) {
        w.value(std::uint64_t{*s.hotspot20_release});
    } else {
        w.null();
    }

    w.key("vendors");
    w.begin_array();
    for (const auto& v : s.vendors) {
        w.begin_object();
        w.field("oui", core::format_oui(v.oui));
        w.field("name", v.name);
        w.end_object();
    }
    w.end_array();
    w.field("element_count", std::uint64_t{s.element_count});
    w.field("problem_count", std::uint64_t{s.problem_count});
    w.end_object();
}

} // namespace

std::string to_json(const DecodedIes& ies, const BssSummary& s, const Localizer& loc,
                    const JsonOptions& opt) {
    JsonWriter w{opt.pretty};
    w.begin_object();
    w.field("schema", json_schema);
    w.field("schema_version", std::int64_t{json_schema_version});
    w.field("locale", loc.locale());

    w.key("summary");
    summary(w, s, loc);

    w.key("overview");
    children(w, describe(s).children, loc, opt);

    w.key("elements");
    w.begin_array();
    for (std::size_t i = 0; i < ies.elements.size(); ++i) {
        const auto& e = ies.elements[i];
        w.begin_object();
        w.field("index", std::uint64_t{i});
        w.field("id", std::uint64_t{e.key.id});
        if (e.key.ext_id) {
            w.field("ext_id", std::uint64_t{*e.key.ext_id});
        }
        if (e.key.oui) {
            w.field("oui", core::format_oui(*e.key.oui));
        }
        if (e.key.vendor_type) {
            w.field("vendor_type", std::uint64_t{*e.key.vendor_type});
        }
        w.field("type", e.type);
        w.field("name", loc.text(e.name));
        w.field("offset", std::uint64_t{e.raw.stream_range.offset});
        w.field("stream_length", std::uint64_t{e.raw.stream_range.length});
        w.field("length", std::uint64_t{e.raw.payload.size()});
        w.field("content_offset", std::uint64_t{e.raw.ext_id ? 1U : 0U});
        w.field("fragmented", e.raw.fragmented());
        w.field("status", status_key(e.status));
        if (opt.include_payload) {
            w.field("payload", to_hex(e.raw.payload));
        }
        w.key("diagnostics");
        diagnostics(w, e.diagnostics, loc);
        if (opt.include_tree) {
            w.key("tree");
            children(w, e.tree.children, loc, opt);
        }
        w.end_object();
    }
    w.end_array();

    w.key("diagnostics");
    diagnostics(w, ies.diagnostics, loc);
    if (ies.trailing) {
        range(w, "trailing", *ies.trailing);
    }
    w.end_object();
    return w.take();
}

} // namespace wifi_analyze
