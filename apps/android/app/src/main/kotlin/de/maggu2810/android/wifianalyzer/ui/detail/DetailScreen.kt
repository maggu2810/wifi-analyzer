// SPDX-License-Identifier: MIT
@file:OptIn(ExperimentalMaterial3Api::class)

package de.maggu2810.android.wifianalyzer.ui.detail

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.data.PlatformInfo
import de.maggu2810.android.wifianalyzer.data.hexToBytes
import de.maggu2810.android.wifianalyzer.data.toHex
import de.maggu2810.android.wifianalyzer.domain.Network
import de.maggu2810.android.wifianalyzer.nativelib.DecodedDocument
import de.maggu2810.android.wifianalyzer.nativelib.Diagnostic
import de.maggu2810.android.wifianalyzer.nativelib.Element
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.components.FlatNode
import de.maggu2810.android.wifianalyzer.ui.components.HexView
import de.maggu2810.android.wifianalyzer.ui.components.InfoChip
import de.maggu2810.android.wifianalyzer.ui.components.KeyValueRow
import de.maggu2810.android.wifianalyzer.ui.components.SectionCard
import de.maggu2810.android.wifianalyzer.ui.components.SignalChart
import de.maggu2810.android.wifianalyzer.ui.components.SignalIndicator
import de.maggu2810.android.wifianalyzer.ui.components.SignalSeries
import de.maggu2810.android.wifianalyzer.ui.components.TreeRow
import de.maggu2810.android.wifianalyzer.ui.components.bandLabel
import de.maggu2810.android.wifianalyzer.ui.components.flatten
import de.maggu2810.android.wifianalyzer.ui.components.yesNo
import de.maggu2810.android.wifianalyzer.ui.networks.rememberNow
import de.maggu2810.android.wifianalyzer.ui.theme.ChartPalette

@Composable
fun DetailScreen(vm: AppViewModel, bssid: String, onBack: () -> Unit) {
    val state by vm.scanState.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val network = state.networks.firstOrNull { it.bssid == bssid }
    var doc by remember { mutableStateOf<DecodedDocument?>(null) }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val context = LocalContext.current

    // Re-decode when the IE content, locale-relevant settings or detail level change.
    val iesKey = network?.observation?.ies?.contentHashCode()
    LaunchedEffect(bssid, iesKey, settings.showDetailFields) {
        doc = vm.decodeDetail(bssid)
    }
    val exportOne = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null && network != null) vm.exportCapture(uri, listOf(network.observation))
    }

    Scaffold(
        contentWindowInsets = WindowInsets.navigationBars,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back)) }
                },
                title = {
                    Column {
                        Text(
                            when {
                                network == null -> bssid
                                network.hidden -> stringResource(R.string.hidden_network)
                                else -> network.ssid
                            },
                            maxLines = 1,
                        )
                        Text(bssid, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                actions = {
                    if (network != null) {
                        IconButton(onClick = {
                            copyToClipboard(context, network.observation.ies.toHex())
                        }) { Icon(Icons.Filled.ContentCopy, stringResource(R.string.action_copy_hex)) }
                        IconButton(onClick = { shareText(context, shareTextFor(network)) }) {
                            Icon(Icons.Filled.Share, stringResource(R.string.action_share))
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (network == null) {
                Text(stringResource(R.string.detail_not_available), Modifier.padding(24.dp))
                return@Column
            }
            val titles = listOf(R.string.detail_tab_overview, R.string.detail_tab_signal, R.string.detail_tab_elements, R.string.detail_tab_raw)
            PrimaryTabRow(selectedTabIndex = tab) {
                titles.forEachIndexed { i, title ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(stringResource(title)) })
                }
            }
            val d = doc
            when {
                d == null -> Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(Modifier.padding(32.dp))
                }
                tab == 0 -> OverviewTab(network, d, settings.showDetailFields)
                tab == 1 -> SignalTab(network)
                tab == 2 -> ElementsTab(d, settings.showDetailFields)
                else -> RawTab(network, onExport = { exportOne.launch("wifi-bss-${bssid.replace(":", "")}.json") })
            }
        }
    }
}

@Composable
private fun OverviewTab(network: Network, doc: DecodedDocument, showDetail: Boolean) {
    val o = network.observation
    val overview = remember(doc, showDetail) { flatten(doc.overview, showDetail) }
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            SectionCard(null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SignalIndicator(o.rssiDbm, stale = network.stale)
                    Column(Modifier.padding(start = 8.dp)) {
                        Text(
                            stringResource(R.string.detail_frequency, o.frequencyMhz, network.channel?.toString() ?: "?", bandLabel(network.band)),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        network.vendor?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
                    }
                }
            }
        }
        item { SectionCard(stringResource(R.string.detail_decoded)) {} }
        items(overview, key = { "o${it.id}" }) { TreeRow(it, selected = false, onClick = null) }
        item { PlatformCard(network.observation.platform, doc) }
        if (doc.diagnostics.isNotEmpty() || doc.elements.any { it.diagnostics.isNotEmpty() }) {
            item {
                SectionCard(stringResource(R.string.detail_diagnostics)) {
                    (doc.diagnostics + doc.elements.flatMap { it.diagnostics }).forEach { DiagnosticText(it) }
                }
            }
        }
    }
}

private val wifiStandardNames = mapOf(1 to "Legacy", 4 to "802.11n", 5 to "802.11ac", 6 to "802.11ax", 7 to "802.11ad", 8 to "802.11be")
private val channelWidthNames = mapOf(0 to "20 MHz", 1 to "40 MHz", 2 to "80 MHz", 3 to "160 MHz", 4 to "80+80 MHz", 5 to "320 MHz")
private val securityTypeNames = mapOf(
    0 to "Open", 1 to "WEP", 2 to "PSK", 3 to "EAP", 4 to "SAE", 5 to "EAP WPA3-Enterprise 192-bit", 6 to "OWE",
    7 to "WAPI-PSK", 8 to "WAPI-CERT", 9 to "EAP WPA3-Enterprise", 10 to "OSEN", 11 to "Passpoint R1/R2",
    12 to "Passpoint R3", 13 to "DPP",
)

@Composable
private fun PlatformCard(p: PlatformInfo, doc: DecodedDocument) {
    val phy = doc.summary.phy
    SectionCard(stringResource(R.string.detail_platform)) {
        p.capabilities?.let { KeyValueRow(stringResource(R.string.platform_capabilities), it, mono = true) }
        p.channelWidth?.let {
            val mismatch = p.channelWidthMhz != null && p.channelWidthMhz != (if (phy.eightyPlusEighty) 160 else phy.channelWidthMhz)
            KeyValueRow(
                stringResource(R.string.platform_channel_width),
                (channelWidthNames[it] ?: it.toString()) + if (mismatch) " ≠ ${phy.channelWidthMhz} MHz" else "",
                warning = mismatch,
            )
        }
        if (p.centerFreq0 != null || p.centerFreq1 != null) {
            val decoded = phy.centerFrequenciesMhz.joinToString(" / ")
            val platform = listOfNotNull(p.centerFreq0, p.centerFreq1).joinToString(" / ")
            KeyValueRow(stringResource(R.string.platform_center_freq), "$platform MHz", warning = decoded.isNotEmpty() && p.centerFreq0 !in phy.centerFrequenciesMhz)
        }
        p.wifiStandard?.let {
            val mismatch = p.generation != null && p.generation != phy.generation
            KeyValueRow(stringResource(R.string.platform_wifi_standard), wifiStandardNames[it] ?: it.toString(), warning = mismatch)
        }
        p.securityTypes?.let { types ->
            KeyValueRow(stringResource(R.string.platform_security_types), types.joinToString(", ") { securityTypeNames[it] ?: it.toString() })
        }
        KeyValueRow(stringResource(R.string.platform_80211mc), yesNo(p.is80211mcResponder))
        p.is80211azNtbResponder?.let { KeyValueRow(stringResource(R.string.platform_80211az), yesNo(it)) }
        p.isTwtResponder?.let { KeyValueRow(stringResource(R.string.platform_twt), yesNo(it)) }
        KeyValueRow(stringResource(R.string.platform_passpoint), yesNo(p.isPasspoint))
        p.operatorFriendlyName?.let { KeyValueRow(stringResource(R.string.platform_operator), it) }
        p.venueName?.let { KeyValueRow(stringResource(R.string.platform_venue), it) }
        p.apMldMacAddress?.let { KeyValueRow(stringResource(R.string.platform_mld_mac), it, mono = true) }
        p.apMloLinkId?.let { KeyValueRow(stringResource(R.string.platform_mlo_link), it.toString()) }
        p.affiliatedMloLinkCount?.takeIf { it > 0 }?.let { KeyValueRow(stringResource(R.string.platform_mlo_links), it.toString()) }
    }
}

@Composable
private fun DiagnosticText(d: Diagnostic) {
    val color = when (d.severity) {
        "error" -> MaterialTheme.colorScheme.error
        "warning" -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text("• ${d.message}", color = color, style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun SignalTab(network: Network) {
    val now = rememberNow()
    val samples = network.history
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            SectionCard(stringResource(R.string.signal_last_minutes, 10)) {
                SignalChart(listOf(SignalSeries(network.ssid, ChartPalette[0], samples)), now, 10 * 60_000L)
            }
        }
        item {
            SectionCard(stringResource(R.string.signal_statistics)) {
                val values = samples.map { it.rssiDbm }
                KeyValueRow(stringResource(R.string.signal_current), stringResource(R.string.unit_dbm, network.rssi))
                if (values.isNotEmpty()) {
                    KeyValueRow(stringResource(R.string.signal_min), stringResource(R.string.unit_dbm, values.min()))
                    KeyValueRow(stringResource(R.string.signal_max), stringResource(R.string.unit_dbm, values.max()))
                    KeyValueRow(stringResource(R.string.signal_avg), "%.1f dBm".format(values.average()))
                }
                KeyValueRow(stringResource(R.string.signal_samples), values.size.toString())
            }
        }
    }
}

@Composable
private fun ElementsTab(doc: DecodedDocument, showDetail: Boolean) {
    var expanded by rememberSaveable { mutableStateOf(setOf<Int>()) }
    var selected by remember { mutableStateOf<Pair<Int, String>?>(null) }
    LazyColumn(contentPadding = PaddingValues(vertical = 8.dp)) {
        doc.elements.forEach { element ->
            elementItems(
                element = element,
                expanded = element.index in expanded,
                showDetail = showDetail,
                selectedId = selected?.takeIf { it.first == element.index }?.second,
                onToggle = {
                    expanded = if (element.index in expanded) expanded - element.index else expanded + element.index
                },
                onSelect = { id -> selected = element.index to id },
            )
        }
    }
}

private fun LazyListScope.elementItems(
    element: Element,
    expanded: Boolean,
    showDetail: Boolean,
    selectedId: String?,
    onToggle: () -> Unit,
    onSelect: (String) -> Unit,
) {
    item(key = "h${element.index}") {
        Row(
            Modifier.fillMaxWidth().clickable(onClick = onToggle).padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(Modifier.weight(1f)) {
                Text(element.name, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(
                    stringResource(R.string.element_header, element.idText, element.length, element.offset),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            when (element.status) {
                "ok" -> Unit
                "unknown" -> InfoChip(stringResource(R.string.element_not_decoded))
                else -> InfoChip(element.status, warning = true)
            }
            if (element.diagnostics.any { it.severity != "info" }) InfoChip("!", warning = true)
            Icon(if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore, null)
        }
    }
    if (expanded) {
        val flat: List<FlatNode> = flatten(element.tree, showDetail)
        items(flat, key = { "e${element.index}${it.id}" }) { f ->
            TreeRow(f, selected = f.id == selectedId, onClick = if (f.node.bytes != null) ({ onSelect(f.id) }) else null)
        }
        item(key = "x${element.index}") {
            val content = element.payload?.hexToBytes()?.let { it.copyOfRange(element.contentOffset.coerceAtMost(it.size), it.size) }
            val range = flat.firstOrNull { it.id == selectedId }?.node?.bytes?.let { b -> b[0] until b[0] + b[1] }
            Column(Modifier.padding(horizontal = 12.dp)) {
                element.diagnostics.forEach { DiagnosticText(it) }
                if (content != null && content.isNotEmpty()) {
                    HexView(content, range)
                    Text(stringResource(R.string.element_hex_hint), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                }
            }
        }
    }
    item(key = "d${element.index}") { HorizontalDivider() }
}

@Composable
private fun RawTab(network: Network, onExport: () -> Unit) {
    val context = LocalContext.current
    val hex = network.observation.ies.toHex()
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            SectionCard(pluralStringResource(R.plurals.raw_title, network.observation.ies.size, network.observation.ies.size)) {
                SelectionContainer {
                    Text(hex.chunked(32).joinToString("\n"), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { copyToClipboard(context, hex) }) { Text(stringResource(R.string.action_copy_hex)) }
                OutlinedButton(onClick = { shareText(context, shareTextFor(network)) }) { Text(stringResource(R.string.action_share)) }
                OutlinedButton(onClick = onExport) { Text(stringResource(R.string.action_export_one)) }
            }
        }
        item {
            Text(stringResource(R.string.raw_cli_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** wpa_cli-like text, accepted by wifi-analyze-cli (`decode` auto-detects it). */
private fun shareTextFor(n: Network): String = buildString {
    appendLine("bssid=${n.bssid}")
    appendLine("freq=${n.observation.frequencyMhz}")
    appendLine("level=${n.rssi}")
    n.observation.platform.capabilities?.let { appendLine("flags=$it") }
    appendLine("ssid=${n.ssid}")
    appendLine("ie=${n.observation.ies.toHex()}")
}

private fun copyToClipboard(context: android.content.Context, text: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    clipboard?.setPrimaryClip(ClipData.newPlainText("IE", text))
}

private fun shareText(context: android.content.Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, null))
}
