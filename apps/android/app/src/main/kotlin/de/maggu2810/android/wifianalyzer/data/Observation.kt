// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

/**
 * One sighting of a BSS as reported by the platform (or read from a capture). Plain Kotlin, no
 * Android types, so domain logic and tests work on the JVM.
 */
data class Observation(
    val bssid: String,
    /** SSID as reported by the platform (decoded SSID from the IEs takes precedence in the UI). */
    val ssid: String,
    val frequencyMhz: Int,
    val rssiDbm: Int,
    /** Wall-clock time of the sighting (ms since epoch). */
    val timestampMs: Long,
    val platform: PlatformInfo = PlatformInfo(),
    /** Raw IE stream (TLVs) rebuilt from the platform's information elements. */
    val ies: ByteArray = ByteArray(0),
) {
    /** Privacy bit derived from the platform capabilities string (null if unknown). */
    val privacy: Boolean?
        get() = platform.capabilities?.let { caps ->
            listOf("WEP", "WPA", "RSN", "SAE", "OWE", "EAP", "PSK").any { caps.contains(it) }
        }

    override fun equals(other: Any?): Boolean =
        other is Observation && bssid == other.bssid && ssid == other.ssid &&
            frequencyMhz == other.frequencyMhz && rssiDbm == other.rssiDbm &&
            timestampMs == other.timestampMs && platform == other.platform && ies.contentEquals(other.ies)

    override fun hashCode(): Int = 31 * bssid.hashCode() + timestampMs.hashCode()
}

/** Values reported by Android next to the IEs; null = not available on this version. */
data class PlatformInfo(
    val capabilities: String? = null,
    /** ScanResult.CHANNEL_WIDTH_* */
    val channelWidth: Int? = null,
    val centerFreq0: Int? = null,
    val centerFreq1: Int? = null,
    /** ScanResult.WIFI_STANDARD_* */
    val wifiStandard: Int? = null,
    val is80211mcResponder: Boolean? = null,
    val is80211azNtbResponder: Boolean? = null,
    val isTwtResponder: Boolean? = null,
    val isPasspoint: Boolean? = null,
    val operatorFriendlyName: String? = null,
    val venueName: String? = null,
    val securityTypes: List<Int>? = null,
    val apMldMacAddress: String? = null,
    val apMloLinkId: Int? = null,
    val affiliatedMloLinkCount: Int? = null,
) {
    /** Channel width in MHz from ScanResult.CHANNEL_WIDTH_* (80+80 reported as 160). */
    val channelWidthMhz: Int?
        get() = when (channelWidth) {
            0 -> 20
            1 -> 40
            2 -> 80
            3 -> 160
            4 -> 160
            5 -> 320
            else -> null
        }

    /** Wi-Fi generation from ScanResult.WIFI_STANDARD_* (0 = legacy). */
    val generation: Int?
        get() = when (wifiStandard) {
            1 -> 0
            4 -> 4
            5 -> 5
            6 -> 6
            7 -> 0 // 802.11ad
            8 -> 7
            else -> null
        }
}

/** Builds an IE TLV stream from (id, idExt, content) triples as delivered by Android. */
fun buildIeStream(elements: List<Triple<Int, Int, ByteArray>>): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    for ((id, idExt, content) in elements) {
        // Android strips the Element ID Extension octet from the content of element 255.
        val payload = if (id == 255) byteArrayOf(idExt.toByte()) + content else content
        if (payload.size > 255) continue // cannot be represented as one TLV
        out.write(id)
        out.write(payload.size)
        out.write(payload)
    }
    return out.toByteArray()
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray? {
    val clean = filter { !it.isWhitespace() && it != ':' && it != '-' }
    if (clean.length % 2 != 0) return null
    return ByteArray(clean.length / 2) { i ->
        val hi = Character.digit(clean[2 * i], 16)
        val lo = Character.digit(clean[2 * i + 1], 16)
        if (hi < 0 || lo < 0) return null
        ((hi shl 4) or lo).toByte()
    }
}

fun macToBytes(mac: String): ByteArray? = mac.hexToBytes()?.takeIf { it.size == 6 }

fun bytesToMac(bytes: ByteArray): String = bytes.joinToString(":") { "%02x".format(it) }
