// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import android.content.Context
import android.net.Uri
import de.maggu2810.android.wifianalyzer.nativelib.WifiAnalyze
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class OuiState(val entries: Int? = null, val updatedMs: Long? = null, val busy: Boolean = false, val error: String? = null)

/** Optional full IEEE vendor database: download or import, stored in the app's files dir. */
class OuiRepository(private val context: Context) {
    private val file = File(context.filesDir, "oui/oui.csv")
    private val _state = MutableStateFlow(OuiState())
    val state: StateFlow<OuiState> = _state.asStateFlow()

    /** Version counter; bumped whenever vendor names may have changed. */
    private val _revision = MutableStateFlow(0)
    val revision: StateFlow<Int> = _revision.asStateFlow()

    suspend fun loadCached() = withContext(Dispatchers.IO) {
        if (!file.exists()) return@withContext
        val entries = WifiAnalyze.loadOuiDatabase(file.readBytes())
        _state.value = OuiState(entries = entries, updatedMs = file.lastModified())
        _revision.value++
    }

    suspend fun download(url: String = DEFAULT_URL) = store {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 20_000
        connection.readTimeout = 120_000
        connection.setRequestProperty("User-Agent", "WifiAnalyzer-Android")
        try {
            if (connection.responseCode !in 200..299) error("HTTP ${connection.responseCode}")
            connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    suspend fun import(uri: Uri) = store {
        context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: error("cannot open file")
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        file.delete()
        WifiAnalyze.clearOuiDatabase()
        _state.value = OuiState()
        _revision.value++
    }

    private suspend fun store(fetch: () -> ByteArray) = withContext(Dispatchers.IO) {
        _state.value = _state.value.copy(busy = true, error = null)
        try {
            val bytes = fetch()
            val entries = WifiAnalyze.loadOuiDatabase(bytes) ?: error("not an IEEE OUI CSV file")
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, "oui.csv.tmp")
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(file)) error("cannot store the file")
            _state.value = OuiState(entries = entries, updatedMs = file.lastModified())
            _revision.value++
        } catch (e: Exception) {
            _state.value = _state.value.copy(busy = false, error = e.message ?: e.toString())
        }
    }

    companion object {
        const val DEFAULT_URL = "https://standards-oui.ieee.org/oui/oui.csv"
    }
}
