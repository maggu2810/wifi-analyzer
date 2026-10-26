// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureCodecTest {
    private val source = CaptureCodec.Source(36, "Test Phone", "0.1.0")
    private val ies = "0007486f6d654e6574".hexToBytes()!!
    private val observation = Observation(
        bssid = "aa:bb:cc:00:11:22",
        ssid = "HomeNet",
        frequencyMhz = 5180,
        rssiDbm = -48,
        timestampMs = 10_000,
        platform = PlatformInfo(capabilities = "[WPA2-PSK-CCMP][ESS]", channelWidth = 2, wifiStandard = 6, securityTypes = listOf(2, 4)),
        ies = ies,
    )

    @Test
    fun roundTrip() {
        val text = CaptureCodec.encode(listOf(observation), source, nowMs = 12_000, anonymizer = null)
        assertTrue(text.contains("\"format\": \"wifi-analyze.capture\""))
        val decoded = CaptureCodec.decode(text, nowMs = 99_000)
        assertEquals(1, decoded.size)
        val o = decoded[0]
        assertEquals(observation.bssid, o.bssid)
        assertEquals(observation.ssid, o.ssid)
        assertEquals(5180, o.frequencyMhz)
        assertEquals(-48, o.rssiDbm)
        assertEquals(10_000, o.timestampMs) // created - age
        assertArrayEquals(ies, o.ies)
        assertEquals(observation.platform.copy(), o.platform)
        assertEquals(true, o.privacy)
    }

    @Test
    fun anonymizerIsApplied() {
        val anonymizer = object : Anonymizer {
            override fun ies(ies: ByteArray) = byteArrayOf(0, 0)
            override fun mac(mac: String) = "02:00:00:00:00:01"
            override fun ssid(ssid: String) = "ssid-x"
        }
        val text = CaptureCodec.encode(listOf(observation), source, 12_000, anonymizer)
        assertFalse(text.contains("HomeNet"))
        assertFalse(text.contains("aa:bb:cc"))
        assertFalse(text.contains("Test Phone"))
        val o = CaptureCodec.decode(text, 0).single()
        assertEquals("02:00:00:00:00:01", o.bssid)
        assertArrayEquals(byteArrayOf(0, 0), o.ies)
    }

    @Test
    fun readsCliCaptures() {
        // Capture written by wifi-analyze-cli (platform "linux-cli", flags instead of capabilities).
        val text = """
            {"format":"wifi-analyze.capture","format_version":1,"created":"2026-10-26T12:00:00Z",
             "source":{"platform":"linux-cli"},
             "scans":[{"timestamp":"2026-10-26T12:00:00Z","bss":[
               {"bssid":"00:11:22:33:44:55","ssid":"OldRouter","freq_mhz":2437,"signal_dbm":-71,
                "age_ms":12000,"capabilities":1073,"platform":{"flags":"[WPA2-PSK-CCMP][ESS]"},
                "ies":"00094f6c64526f75746572","beacon_ies":null}]}]}
        """.trimIndent()
        val o = CaptureCodec.decode(text, 0).single()
        assertEquals("oldrouter", o.ssid.lowercase())
        assertEquals(2437, o.frequencyMhz)
        assertEquals(java.time.Instant.parse("2026-10-26T11:59:48Z").toEpochMilli(), o.timestampMs)
    }

    @Test(expected = CaptureCodec.FormatException::class)
    fun rejectsOtherDocuments() {
        CaptureCodec.decode("""{"schema":"wifi-analyze.decoded"}""", 0)
    }

    @Test
    fun rebuildsIeStreamWithExtensionIds() {
        val stream = buildIeStream(
            listOf(
                Triple(0, 0, "abc".toByteArray()),
                Triple(255, 35, byteArrayOf(1, 2)), // HE Capabilities content without ext id
            ),
        )
        assertEquals("0003616263ff03230102", stream.toHex())
    }
}
