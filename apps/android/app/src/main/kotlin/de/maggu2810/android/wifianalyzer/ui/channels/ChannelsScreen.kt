// SPDX-License-Identifier: MIT
@file:OptIn(ExperimentalMaterial3Api::class)

package de.maggu2810.android.wifianalyzer.ui.channels

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.domain.Network
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.components.ChannelGraph
import de.maggu2810.android.wifianalyzer.ui.components.ChannelSpan
import de.maggu2810.android.wifianalyzer.ui.components.bandLabel
import de.maggu2810.android.wifianalyzer.ui.components.signalColor
import de.maggu2810.android.wifianalyzer.ui.theme.ChartPalette

/** Occupied segments of a network: decoded centers, otherwise the primary channel. */
private fun Network.span(color: androidx.compose.ui.graphics.Color, label: String, highlighted: Boolean): ChannelSpan {
    val phy = summary?.phy
    val centers = phy?.centerFrequenciesMhz?.takeIf { it.isNotEmpty() } ?: listOf(observation.frequencyMhz)
    val segment = if (phy?.eightyPlusEighty == true) 80 else widthMhz
    return ChannelSpan(label, centers, segment, rssi, color, highlighted)
}

@Composable
fun ChannelsScreen(vm: AppViewModel, onOpen: (String) -> Unit, onSettings: () -> Unit, insets: WindowInsets) {
    val networks by vm.visibleNetworks.collectAsStateWithLifecycle()
    var band by rememberSaveable { mutableStateOf("2.4") }
    var highlight by rememberSaveable { mutableStateOf<String?>(null) }
    val inBand = networks.filter { it.band == band && !it.stale }.sortedByDescending { it.rssi }
    val hiddenLabel = stringResource(R.string.hidden_network)
    val spans = inBand.mapIndexed { i, n ->
        n.span(ChartPalette[i % ChartPalette.size], if (n.hidden) hiddenLabel else n.ssid, n.bssid == highlight)
    }
    Scaffold(
        contentWindowInsets = insets,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tab_channels)) },
                actions = { IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, stringResource(R.string.settings_title)) } },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("2.4", "5", "6").forEach { b ->
                    FilterChip(
                        selected = band == b,
                        onClick = { band = b; highlight = null },
                        label = { Text("${bandLabel(b)} (${networks.count { it.band == b && !it.stale }})") },
                    )
                }
            }
            ChannelGraph(
                spans = spans,
                band = band,
                modifier = Modifier.fillMaxWidth().height(300.dp).padding(vertical = 8.dp),
                onTap = { i -> highlight = inBand[i].bssid },
            )
            LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                itemsIndexed(inBand, key = { _, n -> n.bssid }) { i, n ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { if (highlight == n.bssid) onOpen(n.bssid) else highlight = n.bssid }
                            .background(if (highlight == n.bssid) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surface)
                            .padding(6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Box(Modifier.size(12.dp).background(ChartPalette[i % ChartPalette.size], CircleShape))
                        Text(if (n.hidden) hiddenLabel else n.ssid, Modifier.weight(1f), maxLines = 1)
                        Text(
                            stringResource(R.string.channel_width_short, n.channel?.toString() ?: "?", n.widthMhz),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Text(stringResource(R.string.unit_dbm, n.rssi), color = signalColor(n.rssi), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
