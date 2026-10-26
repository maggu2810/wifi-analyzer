// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.domain

import de.maggu2810.android.wifianalyzer.data.Observation
import de.maggu2810.android.wifianalyzer.nativelib.Phy
import de.maggu2810.android.wifianalyzer.nativelib.Roaming
import de.maggu2810.android.wifianalyzer.nativelib.Security
import de.maggu2810.android.wifianalyzer.nativelib.Summary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkListTest {
    private fun network(
        bssid: String,
        ssid: String,
        rssi: Int,
        freq: Int = 2437,
        security: String = "wpa2_personal",
        weak: Boolean = false,
        generation: Int = 4,
        vendor: String? = null,
        hidden: Boolean = false,
        time: Long = 1000,
    ) = Network(
        observation = Observation(bssid, ssid, freq, rssi, time),
        summary = Summary(
            ssid = ssid,
            ssidPresent = true,
            hidden = hidden,
            security = Security(security, security, "disabled", "", rsn = true, wpa1 = false, weak = weak),
            phy = Phy(generation = generation, generationLabel = "Wi-Fi $generation", band = bandOfFrequency(freq)),
            roaming = Roaming(k = false, v = false, r = false, ftOverDs = false),
        ),
        vendor = vendor,
        history = emptyList(),
        firstSeenMs = time,
    )

    private val a = network("00:00:00:00:00:01", "Bravo", -70, freq = 5180, security = "wpa3_personal", generation = 6, vendor = "Zeta")
    private val b = network("00:00:00:00:00:02", "alpha", -40, security = "open", weak = true, vendor = "Acme", time = 3000)
    private val c = network("00:00:00:00:00:03", "", -55, freq = 5975, hidden = true, generation = 7, time = 2000)
    private val all = listOf(a, b, c)

    private fun List<Network>.ids() = map { it.bssid.last() }

    @Test
    fun sortsByEveryKey() {
        assertEquals(listOf('2', '3', '1'), sortNetworks(all, SortKey.SIGNAL).ids())
        assertEquals(listOf('1', '3', '2'), sortNetworks(all, SortKey.SIGNAL, descending = true).ids())
        assertEquals(listOf('2', '1', '3'), sortNetworks(all, SortKey.SSID).ids()) // hidden last, case-insensitive
        assertEquals(listOf('2', '1', '3'), sortNetworks(all, SortKey.CHANNEL).ids())
        assertEquals(listOf('2', '1', '3'), sortNetworks(all, SortKey.BAND).ids())
        assertEquals(listOf('1', '3', '2'), sortNetworks(all, SortKey.SECURITY).ids())
        assertEquals(listOf('3', '1', '2'), sortNetworks(all, SortKey.GENERATION).ids())
        assertEquals(listOf('2', '1', '3'), sortNetworks(all, SortKey.VENDOR).ids())
        assertEquals(listOf('2', '3', '1'), sortNetworks(all, SortKey.LAST_SEEN).ids())
        assertEquals(listOf('1', '2', '3'), sortNetworks(all, SortKey.BSSID).ids())
    }

    @Test
    fun filters() {
        assertEquals(listOf('1'), filterNetworks(all, NetworkFilter(bands = setOf("5"))).ids())
        assertEquals(listOf('1', '2'), filterNetworks(all, NetworkFilter(hideHidden = true)).ids())
        assertEquals(listOf('2'), filterNetworks(all, NetworkFilter(onlyInsecure = true)).ids())
        assertEquals(listOf('2'), filterNetworks(all, NetworkFilter(query = "ALP")).ids())
        assertEquals(listOf('1'), filterNetworks(all, NetworkFilter(query = "zeta")).ids())
        assertEquals(listOf('3'), filterNetworks(all, NetworkFilter(query = ":03")).ids())
        assertTrue(NetworkFilter(query = "x").isActive)
    }

    @Test
    fun groupsBySsidKeepingHiddenSeparate() {
        val a2 = network("00:00:00:00:00:04", "Bravo", -60, freq = 2412)
        val c2 = network("00:00:00:00:00:05", "", -80, hidden = true)
        val groups = groupBySsid(listOf(a, b, a2, c, c2))
        assertEquals(4, groups.size)
        assertEquals(2, groups[0].networks.size)
        assertEquals("00:00:00:00:00:04", groups[0].strongest.bssid)
        assertTrue(groups[2].hidden && groups[3].hidden)
    }

    @Test
    fun historyIsBounded() {
        var h = emptyList<SignalSample>()
        for (i in 0 until 10) h = appendSample(h, SignalSample(i.toLong(), -50), max = 5)
        assertEquals(5, h.size)
        assertEquals(9L, h.last().timestampMs)
        assertEquals(h, appendSample(h, SignalSample(9, -40), max = 5)) // same timestamp ignored
    }

    @Test
    fun bandsFromFrequency() {
        assertEquals("2.4", bandOfFrequency(2412))
        assertEquals("5", bandOfFrequency(5825))
        assertEquals("6", bandOfFrequency(5955))
        assertEquals(null, bandOfFrequency(900))
    }
}
