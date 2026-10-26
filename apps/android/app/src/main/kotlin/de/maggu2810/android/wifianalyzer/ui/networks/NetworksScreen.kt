// SPDX-License-Identifier: MIT
@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package de.maggu2810.android.wifianalyzer.ui.networks

import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconToggleButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.data.ConnectionInfo
import de.maggu2810.android.wifianalyzer.data.DataSource
import de.maggu2810.android.wifianalyzer.domain.Network
import de.maggu2810.android.wifianalyzer.domain.NetworkGroup
import de.maggu2810.android.wifianalyzer.domain.SortKey
import de.maggu2810.android.wifianalyzer.domain.groupBySsid
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.components.InfoChip
import de.maggu2810.android.wifianalyzer.ui.components.SignalIndicator
import de.maggu2810.android.wifianalyzer.ui.components.bandLabel
import de.maggu2810.android.wifianalyzer.ui.components.formatAge
import kotlinx.coroutines.delay

@Composable
fun sortKeyLabel(key: SortKey): String = stringResource(
    when (key) {
        SortKey.SIGNAL -> R.string.sort_signal
        SortKey.SSID -> R.string.sort_ssid
        SortKey.BSSID -> R.string.sort_bssid
        SortKey.CHANNEL -> R.string.sort_channel
        SortKey.BAND -> R.string.sort_band
        SortKey.SECURITY -> R.string.sort_security
        SortKey.GENERATION -> R.string.sort_generation
        SortKey.VENDOR -> R.string.sort_vendor
        SortKey.LAST_SEEN -> R.string.sort_last_seen
    },
)

/** Ticks once per second so ages ("3 s ago") stay current. */
@Composable
fun rememberNow(): Long {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = System.currentTimeMillis()
        }
    }
    return now
}

@Composable
fun NetworksScreen(vm: AppViewModel, onOpen: (String) -> Unit, onSettings: () -> Unit, insets: WindowInsets) {
    val networks by vm.visibleNetworks.collectAsStateWithLifecycle()
    val state by vm.scanState.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val filter by vm.filter.collectAsStateWithLifecycle()
    val scanning by vm.scanning.collectAsStateWithLifecycle()
    val connection by vm.connection.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val now = rememberNow()

    var sortMenu by remember { mutableStateOf(false) }
    var overflow by remember { mutableStateOf(false) }
    var searching by rememberSaveable { mutableStateOf(false) }
    val expandedGroups = remember { mutableStateOf(setOf<String>()) }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) vm.exportCapture(uri)
    }
    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.importCapture(uri)
    }

    Scaffold(
        contentWindowInsets = insets,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.app_name))
                        Text(
                            stringResource(R.string.networks_count, networks.size, state.networks.size),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { searching = !searching }) {
                        Icon(Icons.Filled.Search, stringResource(R.string.action_search))
                    }
                    IconButton(onClick = { sortMenu = true }) {
                        Icon(Icons.AutoMirrored.Filled.Sort, stringResource(R.string.action_sort))
                    }
                    DropdownMenu(expanded = sortMenu, onDismissRequest = { sortMenu = false }) {
                        SortKey.entries.forEach { key ->
                            DropdownMenuItem(
                                text = { Text(sortKeyLabel(key)) },
                                leadingIcon = { if (key == settings.sortKey) Icon(Icons.Filled.Check, null) },
                                onClick = {
                                    vm.updateSettings { it.copy(sortKey = key) }
                                    sortMenu = false
                                },
                            )
                        }
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.sort_reverse)) },
                            leadingIcon = { if (settings.sortDescending) Icon(Icons.Filled.Check, null) },
                            onClick = { vm.updateSettings { it.copy(sortDescending = !it.sortDescending) } },
                        )
                    }
                    IconToggleButton(
                        checked = settings.groupBySsid,
                        onCheckedChange = { checked -> vm.updateSettings { it.copy(groupBySsid = checked) } },
                    ) {
                        Icon(Icons.Filled.Layers, stringResource(R.string.action_group))
                    }
                    IconButton(onClick = { overflow = true }) {
                        Icon(Icons.Filled.MoreVert, stringResource(R.string.action_more))
                    }
                    DropdownMenu(expanded = overflow, onDismissRequest = { overflow = false }) {
                        DropdownMenuItem(text = { Text(stringResource(R.string.action_export)) }, onClick = {
                            overflow = false
                            exportLauncher.launch("wifi-capture-${System.currentTimeMillis() / 1000}.json")
                        })
                        DropdownMenuItem(text = { Text(stringResource(R.string.action_import)) }, onClick = {
                            overflow = false
                            importLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                        })
                        DropdownMenuItem(text = { Text(stringResource(R.string.settings_title)) }, onClick = {
                            overflow = false
                            onSettings()
                        })
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.source == DataSource.Live) {
                ExtendedFloatingActionButton(
                    onClick = { vm.scan() },
                    icon = { Icon(Icons.Filled.Refresh, null) },
                    text = { Text(stringResource(R.string.action_scan)) },
                )
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (searching) {
                OutlinedTextField(
                    value = filter.query,
                    onValueChange = { vm.setFilter(filter.copy(query = it)) },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                    singleLine = true,
                    placeholder = { Text(stringResource(R.string.search_hint)) },
                    trailingIcon = {
                        IconButton(onClick = { vm.setFilter(filter.copy(query = "")); searching = false }) {
                            Icon(Icons.Filled.Clear, stringResource(R.string.action_clear))
                        }
                    },
                )
            }
            LazyRow(
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(listOf("2.4", "5", "6")) { band ->
                    FilterChip(
                        selected = band in filter.bands,
                        onClick = {
                            vm.setFilter(filter.copy(bands = if (band in filter.bands) filter.bands - band else filter.bands + band))
                        },
                        label = { Text(bandLabel(band)) },
                    )
                }
                item {
                    FilterChip(
                        selected = filter.hideHidden,
                        onClick = { vm.setFilter(filter.copy(hideHidden = !filter.hideHidden)) },
                        label = { Text(stringResource(R.string.filter_hide_hidden)) },
                    )
                }
                item {
                    FilterChip(
                        selected = filter.onlyInsecure,
                        onClick = { vm.setFilter(filter.copy(onlyInsecure = !filter.onlyInsecure)) },
                        label = { Text(stringResource(R.string.filter_insecure)) },
                    )
                }
            }
            Banners(vm, state.source, onLocationSettings = {
                context.startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            })
            StatusLine(vm, state.lastUpdateMs, now, settings.autoScan, state.source)

            PullToRefreshBox(isRefreshing = scanning, onRefresh = { vm.scan() }, modifier = Modifier.fillMaxSize()) {
                LazyColumn(
                    contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 4.dp, bottom = 96.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxSize(),
                ) {
                    val conn = connection
                    if (conn != null && state.source == DataSource.Live) {
                        item(key = "connection") { ConnectedCard(conn) { conn.bssid?.let(onOpen) } }
                    }
                    if (networks.isEmpty()) {
                        item(key = "empty") {
                            Text(
                                stringResource(if (state.networks.isEmpty()) R.string.networks_empty else R.string.networks_filtered_empty),
                                Modifier.padding(24.dp),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    if (settings.groupBySsid) {
                        groupBySsid(networks).forEach { group ->
                            val key = if (group.hidden) group.networks.first().bssid else "g:${group.ssid}"
                            item(key = key) {
                                GroupCard(
                                    group = group,
                                    now = now,
                                    connectedBssid = conn?.bssid,
                                    expanded = key in expandedGroups.value,
                                    onToggle = {
                                        expandedGroups.value =
                                            if (key in expandedGroups.value) expandedGroups.value - key else expandedGroups.value + key
                                    },
                                    onOpen = onOpen,
                                )
                            }
                        }
                    } else {
                        items(networks, key = { it.bssid }) { n ->
                            NetworkCard(n, now, connected = n.bssid == conn?.bssid, onClick = { onOpen(n.bssid) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Banners(vm: AppViewModel, source: DataSource, onLocationSettings: () -> Unit) {
    if (source is DataSource.Imported) {
        BannerCard(stringResource(R.string.banner_imported, source.name), stringResource(R.string.action_back_to_live)) {
            vm.backToLive()
        }
        return
    }
    if (!vm.isLocationEnabled) {
        BannerCard(stringResource(R.string.banner_location_off), stringResource(R.string.action_open_settings), onLocationSettings)
    } else if (!vm.isWifiEnabled) {
        BannerCard(stringResource(R.string.banner_wifi_off), null, null)
    }
}

@Composable
private fun BannerCard(text: String, action: String?, onAction: (() -> Unit)?) {
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            if (action != null && onAction != null) {
                TextButton(onClick = onAction) { Text(action) }
            }
        }
    }
}

@Composable
private fun StatusLine(vm: AppViewModel, lastUpdate: Long?, now: Long, autoScan: Boolean, source: DataSource) {
    if (source !is DataSource.Live) return
    val parts = buildList {
        add(
            if (lastUpdate == null) stringResource(R.string.status_no_scan)
            else stringResource(R.string.status_updated, formatAge(now - lastUpdate)),
        )
        add(stringResource(if (autoScan) R.string.status_auto_on else R.string.status_auto_off))
        vm.remainingScanBudget()?.let { add(stringResource(R.string.status_budget, it)) }
    }
    Text(
        parts.joinToString(" · "),
        Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun ConnectedCard(conn: ConnectionInfo, onClick: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            conn.rssiDbm?.let { SignalIndicator(it) }
            Column(Modifier.weight(1f).padding(start = 8.dp)) {
                Text(stringResource(R.string.connected_to), style = MaterialTheme.typography.labelMedium)
                Text(conn.ssid ?: stringResource(R.string.unknown), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                val speeds = listOfNotNull(
                    conn.txLinkSpeedMbps?.let { stringResource(R.string.link_tx, it) },
                    conn.rxLinkSpeedMbps?.let { stringResource(R.string.link_rx, it) },
                    conn.frequencyMhz?.let { stringResource(R.string.unit_mhz, it) },
                )
                if (speeds.isNotEmpty()) {
                    Text(speeds.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
fun NetworkCard(n: Network, now: Long, connected: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val s = n.summary
    Card(
        modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = if (connected) CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer) else CardDefaults.cardColors(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            SignalIndicator(n.rssi, stale = n.stale)
            Column(Modifier.weight(1f).padding(start = 8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    if (n.hidden) stringResource(R.string.hidden_network) else n.ssid,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    color = if (n.hidden || n.stale) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    listOfNotNull(n.bssid, n.vendor).joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    InfoChip(bandLabel(n.band))
                    n.channel?.let { InfoChip(stringResource(R.string.channel_short, it)) }
                    InfoChip(stringResource(R.string.unit_mhz, n.widthMhz))
                    s?.phy?.generationLabel?.let { InfoChip(it, emphasis = n.generation >= 6) }
                    s?.security?.let { InfoChip(it.label, warning = it.weak) }
                    if (connected) InfoChip(stringResource(R.string.connected), emphasis = true)
                }
            }
            Text(
                formatAge(now - n.observation.timestampMs),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline,
            )
        }
    }
}

@Composable
private fun GroupCard(
    group: NetworkGroup,
    now: Long,
    connectedBssid: String?,
    expanded: Boolean,
    onToggle: () -> Unit,
    onOpen: (String) -> Unit,
) {
    if (group.networks.size == 1) {
        val n = group.networks.first()
        NetworkCard(n, now, connected = n.bssid == connectedBssid, onClick = { onOpen(n.bssid) })
        return
    }
    val strongest = group.strongest
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.clickable(onClick = onToggle).padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            SignalIndicator(strongest.rssi)
            Column(Modifier.weight(1f).padding(start = 8.dp)) {
                Text(group.ssid, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    stringResource(R.string.group_aps, group.networks.size, group.networks.mapNotNull { it.band }.distinct().sorted().joinToString(" / ")),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                strongest.summary?.security?.let {
                    Spacer(Modifier.height(2.dp))
                    InfoChip(it.label, warning = it.weak)
                }
            }
            Icon(if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore, null)
        }
        if (expanded) {
            Column(Modifier.padding(start = 12.dp, end = 12.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                group.networks.forEach { n ->
                    NetworkCard(n, now, connected = n.bssid == connectedBssid, onClick = { onOpen(n.bssid) })
                }
            }
        }
    }
}
