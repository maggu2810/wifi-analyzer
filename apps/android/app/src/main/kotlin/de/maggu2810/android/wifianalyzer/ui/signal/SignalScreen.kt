// SPDX-License-Identifier: MIT
@file:OptIn(ExperimentalMaterial3Api::class)

package de.maggu2810.android.wifianalyzer.ui.signal

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.components.SectionCard
import de.maggu2810.android.wifianalyzer.ui.components.SignalChart
import de.maggu2810.android.wifianalyzer.ui.components.SignalSeries
import de.maggu2810.android.wifianalyzer.ui.components.bandLabel
import de.maggu2810.android.wifianalyzer.ui.components.signalColor
import de.maggu2810.android.wifianalyzer.ui.networks.rememberNow
import de.maggu2810.android.wifianalyzer.ui.theme.ChartPalette

private const val TOP_N = 8

@Composable
fun SignalScreen(vm: AppViewModel, onOpen: (String) -> Unit, onSettings: () -> Unit, insets: WindowInsets) {
    val networks by vm.visibleNetworks.collectAsStateWithLifecycle()
    var minutes by rememberSaveable { mutableIntStateOf(5) }
    val now = rememberNow()
    val top = networks.filter { !it.stale }.sortedByDescending { it.rssi }.take(TOP_N)
    val hiddenLabel = stringResource(R.string.hidden_network)
    val series = top.mapIndexed { i, n -> SignalSeries(if (n.hidden) hiddenLabel else n.ssid, ChartPalette[i % ChartPalette.size], n.history) }

    Scaffold(
        contentWindowInsets = insets,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tab_signal)) },
                actions = { IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, stringResource(R.string.settings_title)) } },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.padding(padding), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(2, 5, 15, 30).forEach { m ->
                        FilterChip(selected = minutes == m, onClick = { minutes = m }, label = { Text(stringResource(R.string.minutes_short, m)) })
                    }
                }
            }
            item {
                SectionCard(stringResource(R.string.signal_top_n, top.size)) {
                    SignalChart(series, now, minutes * 60_000L)
                }
            }
            itemsIndexed(top, key = { _, n -> n.bssid }) { i, n ->
                Row(
                    Modifier.fillMaxWidth().clickable { onOpen(n.bssid) }.padding(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(Modifier.size(12.dp).background(ChartPalette[i % ChartPalette.size], CircleShape))
                    Text(if (n.hidden) hiddenLabel else n.ssid, Modifier.weight(1f), maxLines = 1)
                    Text(bandLabel(n.band), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.unit_dbm, n.rssi), color = signalColor(n.rssi), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}
