// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.nativelib

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Kotlin model must parse the golden documents produced by the C++ library. */
class ModelTest {
    private fun golden(name: String): DecodedDocument {
        val text = requireNotNull(javaClass.classLoader?.getResource("$name.json")) { "missing $name.json" }.readText()
        return WifiAnalyze.parseDocument(text)
    }

    @Test
    fun parsesWifi6Document() {
        val doc = golden("wpa2-wpa3-5ghz-ax")
        assertEquals("wifi-analyze.decoded", doc.schema)
        assertEquals(1, doc.schemaVersion)
        assertEquals("HomeNet", doc.summary.ssid)
        assertEquals("wpa2_wpa3_personal", doc.summary.security.type)
        assertEquals(80, doc.summary.phy.channelWidthMhz)
        assertEquals(36, doc.summary.phy.primaryChannel)
        assertEquals(1201.0, doc.summary.phy.maxRateMbps!!, 0.01)
        assertEquals(17, doc.elements.size)
        val rsn = doc.elements.first { it.type == "rsn" }
        assertEquals("48", rsn.idText)
        assertTrue(rsn.tree.isNotEmpty())
        assertTrue(doc.overview.isNotEmpty())
    }

    @Test
    fun parsesWifi7DocumentWithMloAndNeighbors() {
        val doc = golden("wpa3-6ghz-be-mlo")
        assertEquals(7, doc.summary.phy.generation)
        assertEquals("6", doc.summary.phy.band)
        assertEquals(320, doc.summary.phy.channelWidthMhz)
        assertNotNull(doc.summary.mlo)
        assertEquals(1, doc.summary.neighbors.size)
        assertTrue(doc.summary.neighbors[0].coLocated)
        assertEquals("255/108", doc.elements.first { it.type == "eht_capabilities" }.idText)
    }

    @Test
    fun parsesDeviceAndWarnings() {
        val doc = golden("wpa-wpa2-tkip-2ghz-wps")
        assertEquals("ACME Inc", doc.summary.device.manufacturer)
        assertTrue(doc.summary.security.weak)
        val rsn = doc.elements.first { it.type == "rsn" }
        assertTrue(rsn.diagnostics.any { it.severity == "warning" })
        fun anyWarning(nodes: List<TreeNode>): Boolean = nodes.any { it.isWarning || anyWarning(it.children) }
        assertTrue(anyWarning(rsn.tree))
    }
}
