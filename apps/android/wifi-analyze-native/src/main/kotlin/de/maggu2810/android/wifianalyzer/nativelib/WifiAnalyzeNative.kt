// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.nativelib

/** JNI entry points of libwifianalyze (see jni_bridge.cpp). Use [WifiAnalyze] instead. */
internal object WifiAnalyzeNative {
    init {
        System.loadLibrary("wifi_analyze_jni")
    }

    external fun nativeVersion(): String

    external fun nativeDecode(ies: ByteArray, frequencyMhz: Int, privacy: Int, locale: String, flags: Int): String

    external fun nativeDecodeBatch(
        ies: Array<ByteArray>,
        frequenciesMhz: IntArray,
        privacy: IntArray,
        locale: String,
        flags: Int,
    ): String

    external fun nativeLoadOuiDatabase(csv: ByteArray): Int

    external fun nativeClearOuiDatabase()

    external fun nativeOuiName(oui: Int): String?

    external fun nativeAnonymizeIes(ies: ByteArray, salt: Long): ByteArray

    external fun nativeAnonymizeMac(mac: ByteArray, salt: Long): ByteArray

    external fun nativeAnonymizeSsid(ssid: ByteArray, salt: Long): ByteArray

    external fun nativeAvailableLocales(): Array<String>
}
