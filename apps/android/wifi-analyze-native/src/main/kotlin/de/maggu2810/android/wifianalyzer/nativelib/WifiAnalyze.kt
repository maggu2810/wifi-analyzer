// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.nativelib

import kotlinx.serialization.json.Json

/** Input for decoding one BSS. */
class DecodeInput(
    val ies: ByteArray,
    /** Frequency of the primary channel, 0 = unknown. */
    val frequencyMhz: Int = 0,
    /** Privacy bit of the capability information, null = unknown. */
    val privacy: Boolean? = null,
)

/** What to include in decoded documents. */
data class DecodeOptions(
    val tree: Boolean = true,
    val payload: Boolean = true,
    val detail: Boolean = true,
) {
    internal val flags: Int
        get() = (if (tree) 1 else 0) or (if (payload) 2 else 0) or (if (detail) 4 else 0)

    companion object {
        /** Summary, overview and element headers only (for lists). */
        val SUMMARY = DecodeOptions(tree = false, payload = false, detail = false)
    }
}

/**
 * Kotlin facade of libwifianalyze. All domain logic is in the C++ library; this class only
 * transports bytes in and maps the JSON result to [DecodedDocument]. Thread-safe.
 */
object WifiAnalyze {
    val json: Json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    val version: String by lazy { WifiAnalyzeNative.nativeVersion() }

    val availableLocales: List<String> by lazy { WifiAnalyzeNative.nativeAvailableLocales().toList() }

    fun decodeJson(input: DecodeInput, locale: String, options: DecodeOptions = DecodeOptions()): String =
        WifiAnalyzeNative.nativeDecode(
            input.ies,
            input.frequencyMhz,
            input.privacy.toNativePrivacy(),
            locale,
            options.flags,
        )

    fun decode(input: DecodeInput, locale: String, options: DecodeOptions = DecodeOptions()): DecodedDocument =
        parseDocument(decodeJson(input, locale, options))

    /** Decodes many BSSs with one JNI call. */
    fun decodeBatch(
        inputs: List<DecodeInput>,
        locale: String,
        options: DecodeOptions = DecodeOptions.SUMMARY,
    ): List<DecodedDocument> {
        if (inputs.isEmpty()) return emptyList()
        val text = WifiAnalyzeNative.nativeDecodeBatch(
            inputs.map { it.ies }.toTypedArray(),
            inputs.map { it.frequencyMhz }.toIntArray(),
            inputs.map { it.privacy.toNativePrivacy() }.toIntArray(),
            locale,
            options.flags,
        )
        return json.decodeFromString(text)
    }

    /** Loads an IEEE oui.csv; returns the number of entries or null if the file is invalid. */
    fun loadOuiDatabase(csv: ByteArray): Int? = WifiAnalyzeNative.nativeLoadOuiDatabase(csv).takeIf { it >= 0 }

    fun clearOuiDatabase() = WifiAnalyzeNative.nativeClearOuiDatabase()

    /** Vendor name of a MAC address' OUI (null for unknown or locally administered addresses). */
    fun vendorOf(mac: ByteArray): String? {
        if (mac.size < 3 || (mac[0].toInt() and 0x03) != 0) return null
        val oui = ((mac[0].toInt() and 0xff) shl 16) or ((mac[1].toInt() and 0xff) shl 8) or (mac[2].toInt() and 0xff)
        return WifiAnalyzeNative.nativeOuiName(oui)
    }

    fun anonymizeIes(ies: ByteArray, salt: Long): ByteArray = WifiAnalyzeNative.nativeAnonymizeIes(ies, salt)

    fun anonymizeMac(mac: ByteArray, salt: Long): ByteArray = WifiAnalyzeNative.nativeAnonymizeMac(mac, salt)

    fun anonymizeSsid(ssid: ByteArray, salt: Long): ByteArray = WifiAnalyzeNative.nativeAnonymizeSsid(ssid, salt)

    fun parseDocument(text: String): DecodedDocument = json.decodeFromString(text)

    private fun Boolean?.toNativePrivacy(): Int = when (this) {
        null -> -1
        false -> 0
        true -> 1
    }
}
