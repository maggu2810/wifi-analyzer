// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui

import android.app.Application
import android.net.Uri
import android.os.Build
import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import de.maggu2810.android.wifianalyzer.AppContainer
import de.maggu2810.android.wifianalyzer.BuildConfig
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.data.Anonymizer
import de.maggu2810.android.wifianalyzer.data.CaptureCodec
import de.maggu2810.android.wifianalyzer.data.ConnectionInfo
import de.maggu2810.android.wifianalyzer.data.Observation
import de.maggu2810.android.wifianalyzer.data.OuiState
import de.maggu2810.android.wifianalyzer.data.ScanRequestResult
import de.maggu2810.android.wifianalyzer.data.ScanState
import de.maggu2810.android.wifianalyzer.data.Settings
import de.maggu2810.android.wifianalyzer.data.bytesToMac
import de.maggu2810.android.wifianalyzer.data.macToBytes
import de.maggu2810.android.wifianalyzer.domain.Network
import de.maggu2810.android.wifianalyzer.domain.NetworkFilter
import de.maggu2810.android.wifianalyzer.domain.filterNetworks
import de.maggu2810.android.wifianalyzer.domain.sortNetworks
import de.maggu2810.android.wifianalyzer.nativelib.DecodedDocument
import de.maggu2810.android.wifianalyzer.nativelib.WifiAnalyze
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.random.Random

/** A short message for the snackbar. */
data class UiMessage(
    /** String resource, or plurals resource if [quantity] is set. */
    val text: Int,
    val args: List<Any> = emptyList(),
    val quantity: Int? = null,
)

class AppViewModel(private val app: Application, private val c: AppContainer) : ViewModel() {
    val settings: StateFlow<Settings> =
        c.settings.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())
    val scanState: StateFlow<ScanState> = c.scans.state
    val connection: StateFlow<ConnectionInfo?> = c.connection.connection
    val ouiState: StateFlow<OuiState> = c.oui.state
    val scanning: StateFlow<Boolean> = c.scanner.scanning

    private val _filter = MutableStateFlow(NetworkFilter())
    val filter: StateFlow<NetworkFilter> = _filter.asStateFlow()

    private val _permissionsGranted = MutableStateFlow(false)
    val permissionsGranted: StateFlow<Boolean> = _permissionsGranted.asStateFlow()

    private val _messages = Channel<UiMessage>(Channel.BUFFERED)
    val messages = _messages.receiveAsFlow()

    /** Networks after filter and sort (grouping is done by the screen). */
    val visibleNetworks: StateFlow<List<Network>> =
        combine(scanState, settings, filter) { state, s, f ->
            sortNetworks(filterNetworks(state.networks, f), s.sortKey, s.sortDescending)
        }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val isLocationEnabled: Boolean get() = c.scanner.isLocationEnabled
    val isWifiEnabled: Boolean get() = c.scanner.isWifiEnabled
    fun remainingScanBudget(): Int? = c.scanner.remainingScanBudget()

    fun onPermissionsGranted() {
        if (_permissionsGranted.value) return
        _permissionsGranted.value = true
        c.scanner.start()
        c.connection.start()
    }

    /** Runs while the UI is visible: periodic scans if enabled. */
    suspend fun foregroundLoop() {
        c.scans.redecodeAll() // locale may have changed while in background
        while (true) {
            val s = settings.value
            if (_permissionsGranted.value) {
                c.scanner.readResults()
                if (s.autoScan && c.scans.state.value.source is de.maggu2810.android.wifianalyzer.data.DataSource.Live) {
                    c.scanner.requestScan() // silently skipped when throttled
                }
            }
            delay(s.scanIntervalSeconds.coerceIn(5, 600) * 1000L)
        }
    }

    fun scan() {
        if (!_permissionsGranted.value) {
            post(R.string.message_permission_missing)
            return
        }
        when (val r = c.scanner.requestScan()) {
            ScanRequestResult.Started -> Unit
            is ScanRequestResult.Throttled -> {
                val seconds = ((r.nextAllowedAtMs - System.currentTimeMillis()) / 1000).coerceAtLeast(1)
                post(R.string.message_scan_throttled, seconds)
                c.scanner.readResults()
            }
            ScanRequestResult.Rejected -> {
                post(if (c.scanner.isWifiEnabled) R.string.message_scan_rejected else R.string.message_wifi_off)
                c.scanner.readResults()
            }
            ScanRequestResult.NoPermission -> post(R.string.message_permission_missing)
        }
    }

    fun setFilter(filter: NetworkFilter) {
        _filter.value = filter
    }

    fun updateSettings(transform: (Settings) -> Settings) {
        viewModelScope.launch { c.settings.update(transform) }
    }

    fun network(bssid: String): Network? = c.scans.network(bssid)

    suspend fun decodeDetail(bssid: String): DecodedDocument? =
        c.scans.decodeDetail(bssid, settings.value.showDetailFields)

    // --- capture export / import -------------------------------------------------------

    fun exportCapture(uri: Uri, only: List<Observation>? = null) {
        viewModelScope.launch {
            val observations = only ?: c.scans.state.value.networks.map { it.observation }
            val anonymize = settings.first().anonymizeExports
            val salt = Random.nextLong()
            val anonymizer = if (anonymize) {
                object : Anonymizer {
                    override fun ies(ies: ByteArray) = WifiAnalyze.anonymizeIes(ies, salt)
                    override fun mac(mac: String) =
                        macToBytes(mac)?.let { bytesToMac(WifiAnalyze.anonymizeMac(it, salt)) } ?: mac
                    override fun ssid(ssid: String) =
                        WifiAnalyze.anonymizeSsid(ssid.toByteArray(), salt).toString(Charsets.UTF_8)
                }
            } else {
                null
            }
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val text = CaptureCodec.encode(
                        observations,
                        CaptureCodec.Source(Build.VERSION.SDK_INT, "${Build.MANUFACTURER} ${Build.MODEL}", BuildConfig.VERSION_NAME),
                        System.currentTimeMillis(),
                        anonymizer,
                    )
                    app.contentResolver.openOutputStream(uri, "wt")?.use { it.write(text.toByteArray()) }
                        ?: error("cannot open output")
                }
            }
            if (result.isSuccess) {
                _messages.trySend(UiMessage(R.plurals.message_export_done, listOf(observations.size), observations.size))
            } else {
                post(R.string.message_export_failed)
            }
        }
    }

    fun importCapture(uri: Uri) {
        viewModelScope.launch {
            val result = runCatching {
                val text = withContext(Dispatchers.IO) {
                    app.contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
                        ?: error("cannot open input")
                }
                val observations = CaptureCodec.decode(text, System.currentTimeMillis())
                c.scans.importCapture(observations, uri.lastPathSegment ?: "capture")
                observations.size
            }
            result.onSuccess { _messages.trySend(UiMessage(R.plurals.message_import_done, listOf(it), it)) }
                .onFailure { post(R.string.message_import_failed, it.message ?: "") }
        }
    }

    fun backToLive() {
        viewModelScope.launch {
            c.scans.backToLive()
            c.scanner.readResults()
        }
    }

    // --- vendor database ------------------------------------------------------------------

    fun downloadOui() = viewModelScope.launch { c.oui.download() }
    fun importOui(uri: Uri) = viewModelScope.launch { c.oui.import(uri) }
    fun clearOui() = viewModelScope.launch { c.oui.clear() }

    private fun post(@StringRes text: Int, vararg args: Any) {
        _messages.trySend(UiMessage(text, args.toList()))
    }
}
