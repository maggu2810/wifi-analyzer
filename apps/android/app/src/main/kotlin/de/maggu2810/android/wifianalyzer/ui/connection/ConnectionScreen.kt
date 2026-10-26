// SPDX-License-Identifier: MIT
@file:OptIn(ExperimentalMaterial3Api::class)

package de.maggu2810.android.wifianalyzer.ui.connection

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.data.deviceCapabilities
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.components.KeyValueRow
import de.maggu2810.android.wifianalyzer.ui.components.SectionCard
import de.maggu2810.android.wifianalyzer.ui.components.yesNo

private val standardNames = mapOf(1 to "Legacy", 4 to "802.11n (Wi-Fi 4)", 5 to "802.11ac (Wi-Fi 5)", 6 to "802.11ax (Wi-Fi 6)", 7 to "802.11ad", 8 to "802.11be (Wi-Fi 7)")
private val securityNames = mapOf(
    0 to "Open", 1 to "WEP", 2 to "PSK", 3 to "EAP", 4 to "SAE", 5 to "EAP WPA3-Enterprise 192-bit", 6 to "OWE",
    7 to "WAPI-PSK", 8 to "WAPI-CERT", 9 to "EAP WPA3-Enterprise", 10 to "OSEN", 11 to "Passpoint R1/R2",
    12 to "Passpoint R3", 13 to "DPP",
)

private val capabilityLabels = mapOf(
    "wifi_enabled" to R.string.cap_wifi_enabled,
    "band_5ghz" to R.string.cap_band_5ghz,
    "band_6ghz" to R.string.cap_band_6ghz,
    "band_60ghz" to R.string.cap_band_60ghz,
    "standard_11n" to R.string.cap_standard_11n,
    "standard_11ac" to R.string.cap_standard_11ac,
    "standard_11ax" to R.string.cap_standard_11ax,
    "standard_11be" to R.string.cap_standard_11be,
    "wpa3_sae" to R.string.cap_wpa3_sae,
    "wpa3_sae_h2e" to R.string.cap_wpa3_sae_h2e,
    "wpa3_suite_b" to R.string.cap_wpa3_suite_b,
    "owe" to R.string.cap_owe,
    "dpp" to R.string.cap_dpp,
    "p2p" to R.string.cap_p2p,
    "tdls" to R.string.cap_tdls,
    "rtt" to R.string.cap_rtt,
    "aware" to R.string.cap_aware,
    "passpoint" to R.string.cap_passpoint,
    "sta_concurrency_local_only" to R.string.cap_sta_concurrency,
    "scan_throttle" to R.string.cap_scan_throttle,
)

@Composable
fun ConnectionScreen(vm: AppViewModel, onOpen: (String) -> Unit, onSettings: () -> Unit, insets: WindowInsets) {
    val connection by vm.connection.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val capabilities = remember { deviceCapabilities(context) }
    Scaffold(
        contentWindowInsets = insets,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tab_connection)) },
                actions = { IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, stringResource(R.string.settings_title)) } },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.padding(padding), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                val c = connection
                SectionCard(stringResource(R.string.connection_current)) {
                    if (c == null) {
                        Text(stringResource(R.string.connection_none))
                        return@SectionCard
                    }
                    KeyValueRow(stringResource(R.string.connection_ssid), c.ssid ?: stringResource(R.string.unknown))
                    c.bssid?.let { KeyValueRow(stringResource(R.string.connection_bssid), it, mono = true) }
                    c.apMldMacAddress?.let { KeyValueRow(stringResource(R.string.platform_mld_mac), it, mono = true) }
                    c.rssiDbm?.let { KeyValueRow(stringResource(R.string.connection_rssi), stringResource(R.string.unit_dbm, it)) }
                    c.frequencyMhz?.let { KeyValueRow(stringResource(R.string.connection_frequency), stringResource(R.string.unit_mhz, it)) }
                    c.wifiStandard?.let { KeyValueRow(stringResource(R.string.platform_wifi_standard), standardNames[it] ?: it.toString()) }
                    c.securityType?.let { KeyValueRow(stringResource(R.string.connection_security), securityNames[it] ?: it.toString()) }
                    c.txLinkSpeedMbps?.let { KeyValueRow(stringResource(R.string.connection_tx_speed), stringResource(R.string.unit_mbps, it)) }
                    c.rxLinkSpeedMbps?.let { KeyValueRow(stringResource(R.string.connection_rx_speed), stringResource(R.string.unit_mbps, it)) }
                    c.maxTxLinkSpeedMbps?.let { KeyValueRow(stringResource(R.string.connection_max_tx), stringResource(R.string.unit_mbps, it)) }
                    c.maxRxLinkSpeedMbps?.let { KeyValueRow(stringResource(R.string.connection_max_rx), stringResource(R.string.unit_mbps, it)) }
                    if (c.addresses.isNotEmpty()) KeyValueRow(stringResource(R.string.connection_addresses), c.addresses.joinToString("\n"), mono = true)
                    if (c.gateways.isNotEmpty()) KeyValueRow(stringResource(R.string.connection_gateway), c.gateways.joinToString("\n"), mono = true)
                    if (c.dnsServers.isNotEmpty()) KeyValueRow(stringResource(R.string.connection_dns), c.dnsServers.joinToString("\n"), mono = true)
                    c.mtu?.let { KeyValueRow(stringResource(R.string.connection_mtu), it.toString()) }
                    KeyValueRow(stringResource(R.string.connection_validated), yesNo(c.validated))
                    KeyValueRow(stringResource(R.string.connection_metered), yesNo(c.metered))
                    c.downstreamKbps?.let { KeyValueRow(stringResource(R.string.connection_downstream), stringResource(R.string.unit_mbps, it / 1000)) }
                    c.upstreamKbps?.let { KeyValueRow(stringResource(R.string.connection_upstream), stringResource(R.string.unit_mbps, it / 1000)) }
                    c.bssid?.takeIf { vm.network(it) != null }?.let { bssid ->
                        TextButton(onClick = { onOpen(bssid) }) { Text(stringResource(R.string.connection_show_details)) }
                    }
                }
            }
            item {
                SectionCard(stringResource(R.string.device_capabilities)) {
                    capabilities.forEach { cap ->
                        KeyValueRow(capabilityLabels[cap.key]?.let { stringResource(it) } ?: cap.key, yesNo(cap.supported))
                    }
                }
            }
        }
    }
}
