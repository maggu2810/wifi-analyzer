// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.data

import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build

/** One capability of the device's Wi-Fi hardware; null value = not available on this version. */
data class Capability(val key: String, val supported: Boolean?)

/** Queries the WifiManager capability getters available on the running API level. */
fun deviceCapabilities(context: Context): List<Capability> {
    val wifi = context.getSystemService(WifiManager::class.java) ?: return emptyList()
    val pm = context.packageManager
    val s = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val t = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
    return listOf(
        Capability("wifi_enabled", wifi.isWifiEnabled),
        Capability("band_5ghz", wifi.is5GHzBandSupported),
        Capability("band_6ghz", wifi.is6GHzBandSupported),
        Capability("band_60ghz", if (s) wifi.is60GHzBandSupported else null),
        Capability("standard_11n", wifi.isWifiStandardSupported(ScanResult.WIFI_STANDARD_11N)),
        Capability("standard_11ac", wifi.isWifiStandardSupported(ScanResult.WIFI_STANDARD_11AC)),
        Capability("standard_11ax", wifi.isWifiStandardSupported(ScanResult.WIFI_STANDARD_11AX)),
        Capability("standard_11be", if (t) wifi.isWifiStandardSupported(ScanResult.WIFI_STANDARD_11BE) else null),
        Capability("wpa3_sae", wifi.isWpa3SaeSupported),
        Capability("wpa3_sae_h2e", if (s) wifi.isWpa3SaeH2eSupported else null),
        Capability("wpa3_suite_b", wifi.isWpa3SuiteBSupported),
        Capability("owe", wifi.isEnhancedOpenSupported),
        Capability("dpp", wifi.isEasyConnectSupported),
        Capability("p2p", wifi.isP2pSupported),
        Capability("tdls", wifi.isTdlsSupported),
        Capability("rtt", pm.hasSystemFeature(PackageManager.FEATURE_WIFI_RTT)),
        Capability("aware", pm.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)),
        Capability("passpoint", pm.hasSystemFeature(PackageManager.FEATURE_WIFI_PASSPOINT)),
        Capability("sta_concurrency_local_only", if (s) wifi.isStaConcurrencyForLocalOnlyConnectionsSupported else null),
        Capability("scan_throttle", wifi.isScanThrottleEnabled),
    )
}
