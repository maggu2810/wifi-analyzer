// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import android.annotation.SuppressLint
import android.content.Context
import android.location.LocationManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.SystemClock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.Executors

/** Result of a scan request. */
sealed interface ScanRequestResult {
    data object Started : ScanRequestResult

    /** The app's own budget (4 scans / 2 min in foreground) is used up. */
    data class Throttled(val nextAllowedAtMs: Long) : ScanRequestResult

    /** The platform rejected the request (throttled, Wi-Fi off, ...). */
    data object Rejected : ScanRequestResult

    data object NoPermission : ScanRequestResult
}

data class ScanBatch(val observations: List<Observation>, val receivedAtMs: Long)

/**
 * Wraps WifiManager scanning. Results also arrive when other apps or the system scan.
 * Scan throttling (Android 9+): foreground apps may call startScan() 4 times per 2 minutes
 * unless throttling is disabled in the developer options.
 */
class WifiScanner(private val context: Context) {
    private val wifi = context.getSystemService(WifiManager::class.java)
    private val executor = Executors.newSingleThreadExecutor()
    private val ownScans = ArrayDeque<Long>()

    private val _batches = MutableStateFlow(ScanBatch(emptyList(), 0))
    val batches: StateFlow<ScanBatch> = _batches.asStateFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    private var registered = false

    private val callback = object : WifiManager.ScanResultsCallback() {
        override fun onScanResultsAvailable() {
            _scanning.value = false
            readResults()
        }
    }

    val isWifiEnabled: Boolean get() = wifi?.isWifiEnabled == true

    val isScanThrottleEnabled: Boolean get() = wifi?.isScanThrottleEnabled ?: true

    val isLocationEnabled: Boolean
        get() = context.getSystemService(LocationManager::class.java)?.isLocationEnabled == true

    fun start() {
        if (registered || wifi == null) return
        try {
            wifi.registerScanResultsCallback(executor, callback)
            registered = true
        } catch (_: SecurityException) {
            return
        }
        readResults()
    }

    fun stop() {
        if (!registered || wifi == null) return
        runCatching { wifi.unregisterScanResultsCallback(callback) }
        registered = false
    }

    /** Remaining own scans in the current 2 minute window (null = unlimited). */
    fun remainingScanBudget(now: Long = SystemClock.elapsedRealtime()): Int? {
        if (!isScanThrottleEnabled) return null
        prune(now)
        return SCANS_PER_WINDOW - ownScans.size
    }

    @Suppress("DEPRECATION") // startScan() is deprecated but the only way to request a scan.
    fun requestScan(): ScanRequestResult {
        val manager = wifi ?: return ScanRequestResult.Rejected
        val now = SystemClock.elapsedRealtime()
        if (isScanThrottleEnabled) {
            prune(now)
            if (ownScans.size >= SCANS_PER_WINDOW) {
                val next = ownScans.first() + WINDOW_MS
                return ScanRequestResult.Throttled(System.currentTimeMillis() + (next - now))
            }
        }
        return try {
            if (manager.startScan()) {
                ownScans.addLast(now)
                _scanning.value = true
                ScanRequestResult.Started
            } else {
                ScanRequestResult.Rejected
            }
        } catch (_: SecurityException) {
            ScanRequestResult.NoPermission
        }
    }

    private fun prune(now: Long) {
        while (ownScans.isNotEmpty() && now - ownScans.first() > WINDOW_MS) {
            ownScans.removeFirst()
        }
    }

    @SuppressLint("MissingPermission") // checked by the caller; SecurityException handled.
    fun readResults() {
        val manager = wifi ?: return
        val results = try {
            manager.scanResults
        } catch (_: SecurityException) {
            return
        }
        val nowWall = System.currentTimeMillis()
        val nowBootUs = SystemClock.elapsedRealtimeNanos() / 1000
        _batches.value = ScanBatch(results.map { it.toObservation(nowWall, nowBootUs) }, nowWall)
    }

    private companion object {
        const val SCANS_PER_WINDOW = 4
        const val WINDOW_MS = 120_000L
    }
}

/** Maps a ScanResult (all fields available on the running API level). */
internal fun ScanResult.toObservation(nowWallMs: Long, nowBootUs: Long): Observation {
    val ageMs = ((nowBootUs - timestamp) / 1000).coerceAtLeast(0)
    val ssidText = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        wifiSsid?.toString()?.removeSurrounding("\"").orEmpty()
    } else {
        @Suppress("DEPRECATION")
        SSID.orEmpty()
    }
    val elements = informationElements.map { ie ->
        val buffer = ie.bytes
        val content = ByteArray(buffer.remaining())
        buffer.get(content)
        Triple(ie.id, ie.idExt, content)
    }
    val platform = PlatformInfo(
        capabilities = capabilities,
        channelWidth = channelWidth,
        centerFreq0 = centerFreq0.takeIf { it > 0 },
        centerFreq1 = centerFreq1.takeIf { it > 0 },
        wifiStandard = wifiStandard,
        is80211mcResponder = is80211mcResponder,
        is80211azNtbResponder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) is80211azNtbResponder else null,
        isTwtResponder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) isTwtResponder else null,
        isPasspoint = isPasspointNetwork,
        operatorFriendlyName = operatorFriendlyName?.toString()?.takeIf { it.isNotEmpty() },
        venueName = venueName?.toString()?.takeIf { it.isNotEmpty() },
        securityTypes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) securityTypes.toList() else null,
        apMldMacAddress = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) apMldMacAddress?.toString() else null,
        apMloLinkId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) apMloLinkId.takeIf { it >= 0 } else null,
        affiliatedMloLinkCount = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) affiliatedMloLinks.size else null,
    )
    return Observation(
        bssid = BSSID.orEmpty().lowercase(),
        ssid = ssidText,
        frequencyMhz = frequency,
        rssiDbm = level,
        timestampMs = nowWallMs - ageMs,
        platform = platform,
        ies = buildIeStream(elements),
    )
}
