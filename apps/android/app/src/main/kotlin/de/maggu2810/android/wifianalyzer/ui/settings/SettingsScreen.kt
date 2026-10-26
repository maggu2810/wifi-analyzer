// SPDX-License-Identifier: MIT
@file:OptIn(ExperimentalMaterial3Api::class)

package de.maggu2810.android.wifianalyzer.ui.settings

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import de.maggu2810.android.wifianalyzer.BuildConfig
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.nativelib.WifiAnalyze
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.components.KeyValueRow
import de.maggu2810.android.wifianalyzer.ui.components.SectionCard
import java.text.DateFormat
import java.util.Date

@Composable
private fun SwitchRow(title: String, summary: String?, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            summary?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
fun SettingsScreen(vm: AppViewModel, onBack: () -> Unit) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val oui by vm.ouiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val importOui = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.importOui(uri)
    }
    Scaffold(
        contentWindowInsets = WindowInsets.navigationBars,
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back)) } },
                title = { Text(stringResource(R.string.settings_title)) },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.padding(padding), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                SectionCard(stringResource(R.string.settings_scanning)) {
                    SwitchRow(stringResource(R.string.settings_auto_scan), stringResource(R.string.settings_auto_scan_summary), settings.autoScan) { v ->
                        vm.updateSettings { it.copy(autoScan = v) }
                    }
                    Text(stringResource(R.string.settings_interval, settings.scanIntervalSeconds), style = MaterialTheme.typography.bodyLarge)
                    Slider(
                        value = settings.scanIntervalSeconds.toFloat(),
                        onValueChange = { v -> vm.updateSettings { it.copy(scanIntervalSeconds = (v / 5).toInt() * 5) } },
                        valueRange = 10f..120f,
                    )
                    Text(stringResource(R.string.settings_throttle_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            item {
                SectionCard(stringResource(R.string.settings_display)) {
                    SwitchRow(stringResource(R.string.settings_detail_fields), stringResource(R.string.settings_detail_fields_summary), settings.showDetailFields) { v ->
                        vm.updateSettings { it.copy(showDetailFields = v) }
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        OutlinedButton(onClick = {
                            context.startActivity(Intent(Settings.ACTION_APP_LOCALE_SETTINGS, Uri.fromParts("package", context.packageName, null)))
                        }) { Text(stringResource(R.string.settings_language)) }
                    }
                }
            }
            item {
                SectionCard(stringResource(R.string.settings_export)) {
                    SwitchRow(stringResource(R.string.settings_anonymize), stringResource(R.string.settings_anonymize_summary), settings.anonymizeExports) { v ->
                        vm.updateSettings { it.copy(anonymizeExports = v) }
                    }
                }
            }
            item {
                SectionCard(stringResource(R.string.settings_vendor_db)) {
                    Text(
                        if (oui.entries == null) stringResource(R.string.settings_vendor_builtin)
                        else pluralStringResource(
                            R.plurals.settings_vendor_loaded,
                            oui.entries ?: 0,
                            oui.entries ?: 0,
                            oui.updatedMs?.let { DateFormat.getDateInstance().format(Date(it)) } ?: "",
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    if (oui.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                    oui.error?.let { Text(stringResource(R.string.settings_vendor_error, it), color = MaterialTheme.colorScheme.error) }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { vm.downloadOui() }, enabled = !oui.busy) { Text(stringResource(R.string.settings_vendor_download)) }
                        OutlinedButton(onClick = { importOui.launch(arrayOf("text/*", "*/*")) }, enabled = !oui.busy) {
                            Text(stringResource(R.string.settings_vendor_import))
                        }
                    }
                    if (oui.entries != null) {
                        OutlinedButton(onClick = { vm.clearOui() }) { Text(stringResource(R.string.settings_vendor_remove)) }
                    }
                    Text(stringResource(R.string.settings_vendor_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            item {
                SectionCard(stringResource(R.string.settings_about)) {
                    KeyValueRow(stringResource(R.string.about_app_version), BuildConfig.VERSION_NAME)
                    KeyValueRow(stringResource(R.string.about_library_version), WifiAnalyze.version)
                    KeyValueRow(stringResource(R.string.about_license), "MIT")
                    Text(stringResource(R.string.about_third_party), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
