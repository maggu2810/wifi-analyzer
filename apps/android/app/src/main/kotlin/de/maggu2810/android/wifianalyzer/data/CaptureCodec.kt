// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.time.Instant

/** Anonymization hooks (implemented by the native library, replaceable in tests). */
interface Anonymizer {
    fun ies(ies: ByteArray): ByteArray
    fun mac(mac: String): String
    fun ssid(ssid: String): String
}

/** Reads and writes the capture exchange format "wifi-analyze.capture" v1 (docs/data-formats.md). */
object CaptureCodec {
    const val FORMAT = "wifi-analyze.capture"
    const val FORMAT_VERSION = 1

    private val json = Json { prettyPrint = true }

    data class Source(val apiLevel: Int, val device: String, val appVersion: String)

    fun encode(observations: List<Observation>, source: Source, nowMs: Long, anonymizer: Anonymizer?): String {
        val created = Instant.ofEpochMilli(nowMs).toString()
        val bss = buildJsonArray {
            for (o in observations) {
                add(
                    buildJsonObject {
                        put("bssid", anonymizer?.mac(o.bssid) ?: o.bssid)
                        put("ssid", anonymizer?.ssid(o.ssid) ?: o.ssid)
                        put("freq_mhz", o.frequencyMhz)
                        put("signal_dbm", o.rssiDbm)
                        put("age_ms", (nowMs - o.timestampMs).coerceAtLeast(0))
                        put("platform", platformJson(o.platform))
                        put("ies", (anonymizer?.ies(o.ies) ?: o.ies).toHex())
                        put("beacon_ies", JsonNull)
                    },
                )
            }
        }
        val doc = buildJsonObject {
            put("format", FORMAT)
            put("format_version", FORMAT_VERSION)
            put("created", created)
            put(
                "source",
                buildJsonObject {
                    put("platform", "android")
                    put("api_level", source.apiLevel)
                    put("device", if (anonymizer != null) "" else source.device)
                    put("app", "de.maggu2810.android.wifianalyzer")
                    put("app_version", source.appVersion)
                    put("anonymized", anonymizer != null)
                },
            )
            put("scans", buildJsonArray { add(buildJsonObject { put("timestamp", created); put("bss", bss) }) })
        }
        return json.encodeToString(JsonObject.serializer(), doc)
    }

    class FormatException(message: String) : Exception(message)

    /** Parses a capture; all BSSs of all scans (latest sighting per BSSID wins). */
    fun decode(text: String, nowMs: Long): List<Observation> {
        val doc = try {
            json.parseToJsonElement(text).jsonObject
        } catch (e: Exception) {
            throw FormatException("invalid JSON: ${e.message}")
        }
        if (doc["format"]?.jsonPrimitive?.content != FORMAT) throw FormatException("not a $FORMAT document")
        val version = doc["format_version"]?.jsonPrimitive?.intOrNull ?: 0
        if (version > FORMAT_VERSION) throw FormatException("format version $version is not supported")
        val result = LinkedHashMap<String, Observation>()
        for (scan in doc["scans"]?.jsonArray ?: JsonArray(emptyList())) {
            val scanTime = scan.jsonObject["timestamp"]?.jsonPrimitive?.content
                ?.let { runCatching { Instant.parse(it).toEpochMilli() }.getOrNull() } ?: nowMs
            for (b in scan.jsonObject["bss"]?.jsonArray ?: JsonArray(emptyList())) {
                val o = b.jsonObject
                val ies = o["ies"]?.jsonPrimitive?.content?.hexToBytes()
                    ?: throw FormatException("BSS without valid 'ies'")
                val bssid = o["bssid"]?.takeIf { it !is JsonNull }?.jsonPrimitive?.content.orEmpty().lowercase()
                val age = o["age_ms"]?.jsonPrimitive?.longOrNull ?: 0
                val observation = Observation(
                    bssid = bssid.ifEmpty { "bss-${result.size}" },
                    ssid = o["ssid"]?.takeIf { it !is JsonNull }?.jsonPrimitive?.content.orEmpty(),
                    frequencyMhz = o["freq_mhz"]?.jsonPrimitive?.intOrNull ?: 0,
                    rssiDbm = o["signal_dbm"]?.jsonPrimitive?.intOrNull ?: -100,
                    timestampMs = scanTime - age,
                    platform = o["platform"]?.takeIf { it is JsonObject }?.jsonObject?.let(::platformFrom) ?: PlatformInfo(),
                    ies = ies,
                )
                result[observation.bssid] = observation
            }
        }
        if (result.isEmpty()) throw FormatException("capture contains no BSS")
        return result.values.toList()
    }

    private fun platformJson(p: PlatformInfo): JsonObject = buildJsonObject {
        p.capabilities?.let { put("capabilities", it) }
        p.channelWidth?.let { put("channel_width", it) }
        p.centerFreq0?.let { put("center_freq0", it) }
        p.centerFreq1?.let { put("center_freq1", it) }
        p.wifiStandard?.let { put("wifi_standard", it) }
        p.is80211mcResponder?.let { put("is_80211mc_responder", it) }
        p.isPasspoint?.let { put("is_passpoint", it) }
        p.securityTypes?.let { types -> put("security_types", buildJsonArray { types.forEach { add(JsonPrimitive(it)) } }) }
    }

    private fun platformFrom(o: JsonObject): PlatformInfo = PlatformInfo(
        capabilities = o["capabilities"]?.jsonPrimitive?.content,
        channelWidth = o["channel_width"]?.jsonPrimitive?.intOrNull,
        centerFreq0 = o["center_freq0"]?.jsonPrimitive?.intOrNull,
        centerFreq1 = o["center_freq1"]?.jsonPrimitive?.intOrNull,
        wifiStandard = o["wifi_standard"]?.jsonPrimitive?.intOrNull,
        is80211mcResponder = o["is_80211mc_responder"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
        isPasspoint = o["is_passpoint"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
        securityTypes = o["security_types"]?.jsonArray?.mapNotNull { it.jsonPrimitive.intOrNull },
    )
}
