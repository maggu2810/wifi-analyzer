// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiInfo
import android.os.Build
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ConnectionInfo(
    val ssid: String?,
    val bssid: String?,
    val rssiDbm: Int?,
    val frequencyMhz: Int?,
    val linkSpeedMbps: Int?,
    val txLinkSpeedMbps: Int?,
    val rxLinkSpeedMbps: Int?,
    val maxTxLinkSpeedMbps: Int?,
    val maxRxLinkSpeedMbps: Int?,
    /** ScanResult.WIFI_STANDARD_* */
    val wifiStandard: Int?,
    /** WifiInfo.SECURITY_TYPE_* (Android 12+) */
    val securityType: Int?,
    val apMldMacAddress: String?,
    val addresses: List<String> = emptyList(),
    val gateways: List<String> = emptyList(),
    val dnsServers: List<String> = emptyList(),
    val mtu: Int? = null,
    val validated: Boolean = false,
    val metered: Boolean = false,
    val downstreamKbps: Int? = null,
    val upstreamKbps: Int? = null,
)

/** Tracks the current Wi-Fi connection through ConnectivityManager callbacks. */
class ConnectionMonitor(context: Context) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val _connection = MutableStateFlow<ConnectionInfo?>(null)
    val connection: StateFlow<ConnectionInfo?> = _connection.asStateFlow()

    private var capabilities: NetworkCapabilities? = null
    private var link: LinkProperties? = null
    private var registered = false

    private val callback: ConnectivityManager.NetworkCallback =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = update(caps, null)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = update(null, lp)
                override fun onLost(network: Network) = clear()
            }
        } else {
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = update(caps, null)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = update(null, lp)
                override fun onLost(network: Network) = clear()
            }
        }

    fun start() {
        if (registered || connectivity == null) return
        val request = NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build()
        runCatching { connectivity.registerNetworkCallback(request, callback) }.onSuccess { registered = true }
    }

    fun stop() {
        if (!registered) return
        runCatching { connectivity?.unregisterNetworkCallback(callback) }
        registered = false
    }

    @Synchronized
    private fun clear() {
        capabilities = null
        link = null
        _connection.value = null
    }

    @Synchronized
    private fun update(caps: NetworkCapabilities?, lp: LinkProperties?) {
        if (caps != null) capabilities = caps
        if (lp != null) link = lp
        val c = capabilities ?: return
        val info = c.transportInfo as? WifiInfo
        val l = link
        _connection.value = ConnectionInfo(
            ssid = info?.ssid?.removeSurrounding("\"")?.takeIf { it != WifiManagerUnknownSsid },
            bssid = info?.bssid?.lowercase()?.takeIf { it != "02:00:00:00:00:00" },
            rssiDbm = info?.rssi?.takeIf { it > -127 },
            frequencyMhz = info?.frequency?.takeIf { it > 0 },
            linkSpeedMbps = info?.linkSpeed?.takeIf { it > 0 },
            txLinkSpeedMbps = info?.txLinkSpeedMbps?.takeIf { it > 0 },
            rxLinkSpeedMbps = info?.rxLinkSpeedMbps?.takeIf { it > 0 },
            maxTxLinkSpeedMbps = info?.maxSupportedTxLinkSpeedMbps?.takeIf { it > 0 },
            maxRxLinkSpeedMbps = info?.maxSupportedRxLinkSpeedMbps?.takeIf { it > 0 },
            wifiStandard = info?.wifiStandard,
            securityType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) info?.currentSecurityType else null,
            apMldMacAddress = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) info?.apMldMacAddress?.toString() else null,
            addresses = l?.linkAddresses?.map { it.toString() }.orEmpty(),
            gateways = l?.routes?.filter { it.hasGateway() }?.mapNotNull { it.gateway?.hostAddress }?.distinct().orEmpty(),
            dnsServers = l?.dnsServers?.mapNotNull { it.hostAddress }.orEmpty(),
            mtu = l?.mtu?.takeIf { it > 0 },
            validated = c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            metered = !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            downstreamKbps = c.linkDownstreamBandwidthKbps.takeIf { it > 0 },
            upstreamKbps = c.linkUpstreamBandwidthKbps.takeIf { it > 0 },
        )
    }

    private companion object {
        const val WifiManagerUnknownSsid = "<unknown ssid>"
    }
}
