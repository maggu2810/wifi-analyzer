// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import de.maggu2810.android.wifianalyzer.data.hexToBytes
import de.maggu2810.android.wifianalyzer.nativelib.DecodeInput
import de.maggu2810.android.wifianalyzer.nativelib.DecodeOptions
import de.maggu2810.android.wifianalyzer.nativelib.WifiAnalyze
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Runs the real JNI library on the device/emulator (same capture as the C++ golden test). */
@RunWith(AndroidJUnit4::class)
class NativeDecoderTest {
    // testdata/captures/synthetic/wpa2-wpa3-5ghz-ax.hex
    private val ies = "0007486f6d654e657401088c129824b048606c030124050400010000070a444520240417640b1e000b05030020000030180100000fac040100000fac040200000fac02000fac0880002d1aef091bffff0000000000000000000000000000000000000000003d1624050000000000000000000000000000000000000000460502000000007f080400080000000040bf0cb1798b0ffaff0000faff0000c005012a00fcffff16230178c81a40000400000000000000000000fafffaffff0724f43f002afcffdd180050f2020101800003a4000027a4000042435e0062322f00f40120".hexToBytes()!!

    @Test
    fun decodesLikeTheCppLibrary() {
        val doc = WifiAnalyze.decode(DecodeInput(ies, 5180, true), "en")
        assertEquals("wifi-analyze.decoded", doc.schema)
        assertEquals("HomeNet", doc.summary.ssid)
        assertEquals("wpa2_wpa3_personal", doc.summary.security.type)
        assertEquals(80, doc.summary.phy.channelWidthMhz)
        assertEquals(listOf(5210), doc.summary.phy.centerFrequenciesMhz)
        assertEquals(1201.0, doc.summary.phy.maxRateMbps!!, 0.01)
        assertEquals(17, doc.elements.size)
        assertTrue(doc.elements.all { it.status == "ok" })
        assertTrue(doc.elements.first { it.type == "rsn" }.tree.isNotEmpty())
    }

    @Test
    fun batchDecodingAndLocales() {
        val docs = WifiAnalyze.decodeBatch(listOf(DecodeInput(ies), DecodeInput(ies.copyOf(9))), "de-DE", DecodeOptions.SUMMARY)
        assertEquals(2, docs.size)
        assertEquals("de", docs[0].locale)
        assertTrue(docs[0].elements.first().tree.isEmpty())
        assertEquals("HomeNet", docs[1].summary.ssid)
        assertTrue("de" in WifiAnalyze.availableLocales)
    }

    @Test
    fun anonymizationAndVendors() {
        val anon = WifiAnalyze.anonymizeIes(ies, 42)
        val doc = WifiAnalyze.decode(DecodeInput(anon), "en")
        assertNotEquals("HomeNet", doc.summary.ssid)
        assertTrue(doc.summary.ssid.startsWith("ssid-"))
        assertEquals("Microsoft", WifiAnalyze.vendorOf(byteArrayOf(0x00, 0x50, 0xf2.toByte(), 1, 2, 3)))
        val entries = WifiAnalyze.loadOuiDatabase(
            "Registry,Assignment,Organization Name,Organization Address\nMA-L,A4BBCC,Test Vendor,x\n".toByteArray(),
        )
        assertEquals(1, entries)
        assertEquals("Test Vendor", WifiAnalyze.vendorOf(byteArrayOf(0xa4.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0, 0, 0)))
        WifiAnalyze.clearOuiDatabase()
        assertEquals(null, WifiAnalyze.vendorOf(byteArrayOf(0xa4.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0, 0, 0)))
    }
}
