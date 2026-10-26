// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import de.maggu2810.android.wifianalyzer.domain.SortKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

data class Settings(
    val autoScan: Boolean = true,
    val scanIntervalSeconds: Int = 30,
    val sortKey: SortKey = SortKey.SIGNAL,
    val sortDescending: Boolean = false,
    val groupBySsid: Boolean = false,
    val showDetailFields: Boolean = false,
    val anonymizeExports: Boolean = true,
)

private val Context.dataStore by preferencesDataStore(name = "settings")

class SettingsRepository(private val context: Context) {
    private object Keys {
        val autoScan = booleanPreferencesKey("auto_scan")
        val interval = intPreferencesKey("scan_interval_s")
        val sortKey = stringPreferencesKey("sort_key")
        val sortDescending = booleanPreferencesKey("sort_descending")
        val group = booleanPreferencesKey("group_by_ssid")
        val detail = booleanPreferencesKey("show_detail_fields")
        val anonymize = booleanPreferencesKey("anonymize_exports")
    }

    val settings: Flow<Settings> = context.dataStore.data.map { p -> p.toSettings() }

    private fun Preferences.toSettings() = Settings(
        autoScan = this[Keys.autoScan] ?: true,
        scanIntervalSeconds = this[Keys.interval] ?: 30,
        sortKey = this[Keys.sortKey]?.let { runCatching { SortKey.valueOf(it) }.getOrNull() } ?: SortKey.SIGNAL,
        sortDescending = this[Keys.sortDescending] ?: false,
        groupBySsid = this[Keys.group] ?: false,
        showDetailFields = this[Keys.detail] ?: false,
        anonymizeExports = this[Keys.anonymize] ?: true,
    )

    suspend fun update(transform: (Settings) -> Settings) {
        context.dataStore.edit { p ->
            val s = transform(p.toSettings())
            p[Keys.autoScan] = s.autoScan
            p[Keys.interval] = s.scanIntervalSeconds
            p[Keys.sortKey] = s.sortKey.name
            p[Keys.sortDescending] = s.sortDescending
            p[Keys.group] = s.groupBySsid
            p[Keys.detail] = s.showDetailFields
            p[Keys.anonymize] = s.anonymizeExports
        }
    }
}
