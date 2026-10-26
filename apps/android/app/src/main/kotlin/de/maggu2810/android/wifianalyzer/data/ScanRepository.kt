// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import de.maggu2810.android.wifianalyzer.domain.Network
import de.maggu2810.android.wifianalyzer.domain.SignalSample
import de.maggu2810.android.wifianalyzer.domain.appendSample
import de.maggu2810.android.wifianalyzer.nativelib.DecodeInput
import de.maggu2810.android.wifianalyzer.nativelib.DecodeOptions
import de.maggu2810.android.wifianalyzer.nativelib.DecodedDocument
import de.maggu2810.android.wifianalyzer.nativelib.Summary
import de.maggu2810.android.wifianalyzer.nativelib.WifiAnalyze
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Locale

sealed interface DataSource {
    data object Live : DataSource

    data class Imported(val name: String) : DataSource
}

data class ScanState(
    val networks: List<Network> = emptyList(),
    val lastUpdateMs: Long? = null,
    val source: DataSource = DataSource.Live,
)

/**
 * Merges scan results into networks with signal history and decoded summaries. Decoding runs
 * in one JNI batch call per scan; results are cached per (BSSID, IE content, locale).
 */
class ScanRepository(
    private val scope: CoroutineScope,
    private val scanner: WifiScanner,
    private val oui: OuiRepository,
) {
    private val mutex = Mutex()
    private val _state = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = _state.asStateFlow()

    private data class CacheKey(val bssid: String, val iesHash: Int, val frequency: Int)

    private val summaries = HashMap<CacheKey, Summary>()
    private val vendors = HashMap<String, String?>()
    private var cacheLocale: String = ""

    init {
        scope.launch {
            scanner.batches.collect { batch ->
                if (_state.value.source == DataSource.Live && batch.receivedAtMs > 0) {
                    ingest(batch.observations, batch.receivedAtMs)
                }
            }
        }
        scope.launch {
            oui.revision.drop(1).collect {
                mutex.withLock { vendors.clear() }
                redecodeAll()
            }
        }
    }

    val locale: String get() = Locale.getDefault().toLanguageTag()

    fun network(bssid: String): Network? = _state.value.networks.firstOrNull { it.bssid == bssid }

    /** Re-decodes everything (e.g. after a locale or vendor database change). */
    fun redecodeAll() {
        scope.launch {
            mutex.withLock {
                summaries.clear()
                val current = _state.value
                val updated = decodeSummaries(current.networks.map { it.observation })
                _state.value = current.copy(
                    networks = current.networks.map { n ->
                        n.copy(summary = updated[n.bssid] ?: n.summary, vendor = vendorOf(n.bssid))
                    },
                )
            }
        }
    }

    suspend fun importCapture(observations: List<Observation>, name: String) = mutex.withLock {
        summaries.clear()
        val decoded = decodeSummaries(observations)
        _state.value = ScanState(
            networks = observations.map { o ->
                Network(
                    observation = o,
                    summary = decoded[o.bssid],
                    vendor = vendorOf(o.bssid),
                    history = listOf(SignalSample(o.timestampMs, o.rssiDbm)),
                    firstSeenMs = o.timestampMs,
                )
            },
            lastUpdateMs = observations.maxOfOrNull { it.timestampMs },
            source = DataSource.Imported(name),
        )
    }

    suspend fun backToLive() {
        mutex.withLock {
            summaries.clear()
            _state.value = ScanState()
        }
        val batch = scanner.batches.value
        if (batch.receivedAtMs > 0) ingest(batch.observations, batch.receivedAtMs)
    }

    /** Full decode (element trees, payloads) for the detail screen. */
    suspend fun decodeDetail(bssid: String, includeDetailFields: Boolean): DecodedDocument? {
        val o = network(bssid)?.observation ?: return null
        return withContext(Dispatchers.Default) {
            WifiAnalyze.decode(
                DecodeInput(o.ies, o.frequencyMhz, o.privacy),
                locale,
                DecodeOptions(tree = true, payload = true, detail = includeDetailFields),
            )
        }
    }

    private suspend fun ingest(observations: List<Observation>, receivedAtMs: Long) = mutex.withLock {
        val decoded = decodeSummaries(observations)
        val previous = _state.value.networks.associateBy { it.bssid }
        val seen = HashSet<String>()
        val merged = ArrayList<Network>(observations.size + previous.size)
        for (o in observations) {
            if (o.bssid.isEmpty() || !seen.add(o.bssid)) continue
            val old = previous[o.bssid]
            merged += Network(
                observation = o,
                summary = decoded[o.bssid] ?: old?.summary,
                vendor = vendorOf(o.bssid),
                history = appendSample(old?.history.orEmpty(), SignalSample(o.timestampMs, o.rssiDbm)),
                firstSeenMs = old?.firstSeenMs ?: o.timestampMs,
                stale = false,
            )
        }
        // Keep recently seen networks that are missing in this scan, marked stale.
        for ((bssid, n) in previous) {
            if (bssid !in seen && receivedAtMs - n.observation.timestampMs < STALE_KEEP_MS) {
                merged += n.copy(stale = true)
            }
        }
        _state.value = _state.value.copy(networks = merged, lastUpdateMs = receivedAtMs)
    }

    /** Decodes summaries for observations not in the cache (one JNI call). Caller holds the mutex. */
    private suspend fun decodeSummaries(observations: List<Observation>): Map<String, Summary> =
        withContext(Dispatchers.Default) {
            val loc = locale
            if (loc != cacheLocale) {
                summaries.clear()
                cacheLocale = loc
            }
            val missing = observations.filter { CacheKey(it.bssid, it.ies.contentHashCode(), it.frequencyMhz) !in summaries }
            if (missing.isNotEmpty()) {
                val docs = WifiAnalyze.decodeBatch(missing.map { DecodeInput(it.ies, it.frequencyMhz, it.privacy) }, loc)
                missing.zip(docs).forEach { (o, doc) ->
                    summaries[CacheKey(o.bssid, o.ies.contentHashCode(), o.frequencyMhz)] = doc.summary
                }
            }
            observations.mapNotNull { o ->
                summaries[CacheKey(o.bssid, o.ies.contentHashCode(), o.frequencyMhz)]?.let { o.bssid to it }
            }.toMap()
        }

    private fun vendorOf(bssid: String): String? = vendors.getOrPut(bssid) {
        macToBytes(bssid)?.let { WifiAnalyze.vendorOf(it) }
    }

    private companion object {
        const val STALE_KEEP_MS = 5 * 60_000L
    }
}
