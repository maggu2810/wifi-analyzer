// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.domain

import de.maggu2810.android.wifianalyzer.data.Observation
import de.maggu2810.android.wifianalyzer.nativelib.Summary

data class SignalSample(val timestampMs: Long, val rssiDbm: Int)

/** A BSS with its latest observation, decoded summary and signal history. */
data class Network(
    val observation: Observation,
    val summary: Summary?,
    val vendor: String?,
    val history: List<SignalSample>,
    val firstSeenMs: Long,
    /** Not contained in the latest scan. */
    val stale: Boolean = false,
) {
    val bssid: String get() = observation.bssid
    val rssi: Int get() = observation.rssiDbm

    val hidden: Boolean
        get() = summary?.let { !it.ssidPresent || it.hidden } ?: observation.ssid.isEmpty()

    /** SSID for display; empty for hidden networks. */
    val ssid: String
        get() = summary?.takeIf { it.ssidPresent && !it.hidden }?.ssid ?: observation.ssid

    val band: String?
        get() = summary?.phy?.band ?: bandOfFrequency(observation.frequencyMhz)

    val channel: Int? get() = summary?.phy?.primaryChannel

    val widthMhz: Int get() = summary?.phy?.channelWidthMhz ?: observation.platform.channelWidthMhz ?: 20

    val generation: Int get() = summary?.phy?.generation ?: observation.platform.generation ?: 0
}

fun bandOfFrequency(mhz: Int): String? = when (mhz) {
    in 2400..2500 -> "2.4"
    in 4900..5924 -> "5"
    in 5925..7125 -> "6"
    in 57000..71000 -> "60"
    else -> null
}

enum class SortKey { SIGNAL, SSID, BSSID, CHANNEL, BAND, SECURITY, GENERATION, VENDOR, LAST_SEEN }

data class NetworkFilter(
    val query: String = "",
    val bands: Set<String> = emptySet(),
    val hideHidden: Boolean = false,
    val onlyInsecure: Boolean = false,
) {
    val isActive: Boolean get() = query.isNotBlank() || bands.isNotEmpty() || hideHidden || onlyInsecure
}

/** Security strength order used for sorting (higher = stronger). */
fun securityRank(type: String?): Int = when (type) {
    "wpa3_enterprise_192" -> 14
    "wpa3_enterprise" -> 13
    "wpa3_personal" -> 12
    "wpa2_wpa3_enterprise" -> 11
    "wpa2_wpa3_personal" -> 10
    "enhanced_open" -> 9
    "wpa2_enterprise" -> 8
    "wpa2_personal" -> 7
    "other" -> 6
    "wpa_wpa2_enterprise" -> 5
    "wpa_wpa2_personal" -> 4
    "wpa_enterprise" -> 3
    "wpa_personal" -> 2
    "enhanced_open_transition" -> 1
    else -> 0 // open, WEP, unknown
}

fun filterNetworks(networks: List<Network>, filter: NetworkFilter): List<Network> {
    val query = filter.query.trim().lowercase()
    return networks.filter { n ->
        (filter.bands.isEmpty() || n.band in filter.bands) &&
            (!filter.hideHidden || !n.hidden) &&
            (!filter.onlyInsecure || n.summary?.security?.weak == true) &&
            (
                query.isEmpty() ||
                    n.ssid.lowercase().contains(query) ||
                    n.bssid.contains(query) ||
                    (n.vendor?.lowercase()?.contains(query) == true)
                )
    }
}

/**
 * Sorts networks. `descending = false` is the natural order of each key: strongest signal,
 * A..Z, lowest channel, strongest security, newest generation, most recently seen first.
 */
fun sortNetworks(networks: List<Network>, key: SortKey, descending: Boolean = false): List<Network> {
    val comparator: Comparator<Network> = when (key) {
        SortKey.SIGNAL -> compareByDescending { it.rssi }
        SortKey.SSID -> compareBy<Network> { it.hidden }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.ssid }
        SortKey.BSSID -> compareBy { it.bssid }
        SortKey.CHANNEL -> compareBy { it.observation.frequencyMhz }
        SortKey.BAND -> compareBy<Network> { it.band?.toDoubleOrNull() ?: Double.MAX_VALUE }.thenByDescending { it.rssi }
        SortKey.SECURITY -> compareByDescending { securityRank(it.summary?.security?.type) }
        SortKey.GENERATION -> compareByDescending { it.generation }
        SortKey.VENDOR -> compareBy<Network> { it.vendor == null }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.vendor.orEmpty() }
        SortKey.LAST_SEEN -> compareByDescending { it.observation.timestampMs }
    }
    // Stable secondary order: signal, then BSSID.
    val full = comparator.thenByDescending { it.rssi }.thenBy { it.bssid }
    val sorted = networks.sortedWith(full)
    return if (descending) sorted.reversed() else sorted
}

data class NetworkGroup(val ssid: String, val hidden: Boolean, val networks: List<Network>) {
    val strongest: Network get() = networks.maxBy { it.rssi }
}

/** Groups by SSID (hidden networks individually), preserving the order of first appearance. */
fun groupBySsid(networks: List<Network>): List<NetworkGroup> {
    val groups = LinkedHashMap<String, MutableList<Network>>()
    for (n in networks) {
        val key = if (n.hidden) "\u0000${n.bssid}" else n.ssid
        groups.getOrPut(key) { mutableListOf() }.add(n)
    }
    return groups.values.map { NetworkGroup(it.first().ssid, it.first().hidden, it) }
}

/** Appends a sample and keeps at most [max] samples. */
fun appendSample(history: List<SignalSample>, sample: SignalSample, max: Int = 600): List<SignalSample> {
    if (history.lastOrNull()?.timestampMs == sample.timestampMs) return history
    val out = if (history.size >= max) history.drop(history.size - max + 1) else history
    return out + sample
}
