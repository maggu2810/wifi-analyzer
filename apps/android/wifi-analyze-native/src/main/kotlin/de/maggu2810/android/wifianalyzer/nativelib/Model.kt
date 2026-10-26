// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.nativelib

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

// Kotlin model of the "wifi-analyze.decoded" JSON schema version 1 (docs/data-formats.md).

@Serializable
data class DecodedDocument(
    val schema: String,
    @SerialName("schema_version") val schemaVersion: Int,
    val locale: String,
    val summary: Summary,
    val overview: List<TreeNode> = emptyList(),
    val elements: List<Element> = emptyList(),
    val diagnostics: List<Diagnostic> = emptyList(),
    val trailing: List<Int>? = null,
)

@Serializable
data class TreeNode(
    val key: String,
    val label: String,
    /** Display text produced by the library; null for group nodes. */
    val text: String? = null,
    val value: JsonElement? = null,
    @SerialName("value_name") val valueName: String? = null,
    val unit: String? = null,
    /** [offset, length] relative to the element content. */
    val bytes: List<Int>? = null,
    /** [first, count], LSB-first within [bytes]. */
    val bits: List<Int>? = null,
    val significance: String? = null,
    val children: List<TreeNode> = emptyList(),
) {
    val isWarning: Boolean get() = significance == "warning"
    val isDetail: Boolean get() = significance == "detail"

    /** List entries (key "common_item") are rendered as bullets. */
    val isListItem: Boolean get() = key == "common_item"
}

@Serializable
data class Diagnostic(
    val severity: String,
    val key: String,
    val message: String,
    val args: List<String> = emptyList(),
    val bytes: List<Int>? = null,
)

@Serializable
data class Element(
    val index: Int,
    val id: Int,
    @SerialName("ext_id") val extId: Int? = null,
    val oui: String? = null,
    @SerialName("vendor_type") val vendorType: Int? = null,
    val type: String,
    val name: String,
    val offset: Int,
    @SerialName("stream_length") val streamLength: Int,
    val length: Int,
    @SerialName("content_offset") val contentOffset: Int,
    val fragmented: Boolean = false,
    val status: String,
    val payload: String? = null,
    val diagnostics: List<Diagnostic> = emptyList(),
    val tree: List<TreeNode> = emptyList(),
) {
    /** "48", "255/35", "221 00:50:f2/2" */
    val idText: String
        get() = when {
            extId != null -> "255/$extId"
            oui != null -> "221 $oui" + (vendorType?.let { "/$it" } ?: "")
            else -> id.toString()
        }
}

@Serializable
data class Suite(val suite: String, val name: String)

@Serializable
data class Security(
    val type: String,
    val label: String,
    val pmf: String,
    @SerialName("pmf_label") val pmfLabel: String,
    val rsn: Boolean,
    val wpa1: Boolean,
    val weak: Boolean,
    @SerialName("sae_h2e") val saeH2e: Boolean = false,
    @SerialName("sae_pk") val saePk: Boolean = false,
    val akms: List<Suite> = emptyList(),
    @SerialName("pairwise_ciphers") val pairwiseCiphers: List<Suite> = emptyList(),
    @SerialName("group_cipher") val groupCipher: Suite? = null,
    @SerialName("group_management_cipher") val groupManagementCipher: Suite? = null,
)

@Serializable
data class Phy(
    val generation: Int,
    @SerialName("generation_label") val generationLabel: String,
    val standards: List<String> = emptyList(),
    /** "2.4", "5", "6", "60" or null */
    val band: String? = null,
    @SerialName("band_label") val bandLabel: String = "",
    @SerialName("primary_channel") val primaryChannel: Int? = null,
    @SerialName("primary_frequency_mhz") val primaryFrequencyMhz: Int? = null,
    @SerialName("channel_width_mhz") val channelWidthMhz: Int = 20,
    @SerialName("eighty_plus_eighty") val eightyPlusEighty: Boolean = false,
    @SerialName("center_frequencies_mhz") val centerFrequenciesMhz: List<Int> = emptyList(),
    @SerialName("punctured_subchannels") val puncturedSubchannels: Int? = null,
    @SerialName("max_spatial_streams") val maxSpatialStreams: Int = 0,
    @SerialName("max_rate_mbps") val maxRateMbps: Double? = null,
    @SerialName("max_legacy_rate_mbps") val maxLegacyRateMbps: Double? = null,
)

@Serializable
data class BssLoad(
    @SerialName("station_count") val stationCount: Int,
    @SerialName("channel_utilization") val channelUtilization: Int,
    @SerialName("channel_utilization_percent") val channelUtilizationPercent: Double,
    @SerialName("available_admission_capacity") val availableAdmissionCapacity: Int = 0,
)

@Serializable
data class Roaming(val k: Boolean, val v: Boolean, val r: Boolean, @SerialName("ft_over_ds") val ftOverDs: Boolean)

@Serializable
data class Mlo(
    @SerialName("mld_mac") val mldMac: String? = null,
    @SerialName("link_id") val linkId: Int? = null,
    @SerialName("max_simultaneous_links") val maxSimultaneousLinks: Int? = null,
    @SerialName("reported_links") val reportedLinks: Int = 0,
)

@Serializable
data class Neighbor(
    @SerialName("operating_class") val operatingClass: Int,
    val channel: Int,
    val band: String? = null,
    val bssid: String? = null,
    @SerialName("same_ssid") val sameSsid: Boolean = false,
    @SerialName("co_located") val coLocated: Boolean = false,
)

@Serializable
data class Device(
    val manufacturer: String = "",
    @SerialName("model_name") val modelName: String = "",
    @SerialName("model_number") val modelNumber: String = "",
    @SerialName("device_name") val deviceName: String = "",
    @SerialName("serial_number") val serialNumber: String = "",
) {
    val isEmpty: Boolean
        get() = manufacturer.isEmpty() && modelName.isEmpty() && modelNumber.isEmpty() &&
            deviceName.isEmpty() && serialNumber.isEmpty()
}

@Serializable
data class VendorTag(val oui: String, val name: String = "")

@Serializable
data class Summary(
    val ssid: String,
    @SerialName("ssid_hex") val ssidHex: String = "",
    @SerialName("ssid_present") val ssidPresent: Boolean,
    val hidden: Boolean,
    val security: Security,
    val phy: Phy,
    @SerialName("bss_load") val bssLoad: BssLoad? = null,
    val country: String = "",
    val roaming: Roaming,
    val wmm: Boolean = false,
    val uapsd: Boolean = false,
    @SerialName("bss_color") val bssColor: Int? = null,
    @SerialName("twt_responder") val twtResponder: Boolean = false,
    val mlo: Mlo? = null,
    val neighbors: List<Neighbor> = emptyList(),
    @SerialName("nontransmitted_bssids") val nontransmittedBssids: Int = 0,
    val device: Device = Device(),
    @SerialName("access_network_type") val accessNetworkType: Int? = null,
    val internet: Boolean? = null,
    @SerialName("hotspot20_release") val hotspot20Release: Int? = null,
    val vendors: List<VendorTag> = emptyList(),
    @SerialName("element_count") val elementCount: Int = 0,
    @SerialName("problem_count") val problemCount: Int = 0,
)
