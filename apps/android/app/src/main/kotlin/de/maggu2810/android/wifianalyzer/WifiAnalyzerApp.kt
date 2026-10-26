// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer

import android.app.Application
import de.maggu2810.android.wifianalyzer.data.ConnectionMonitor
import de.maggu2810.android.wifianalyzer.data.OuiRepository
import de.maggu2810.android.wifianalyzer.data.ScanRepository
import de.maggu2810.android.wifianalyzer.data.SettingsRepository
import de.maggu2810.android.wifianalyzer.data.WifiScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Manual dependency container (small app, no DI framework). */
class AppContainer(app: Application) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val scanner = WifiScanner(app)
    val connection = ConnectionMonitor(app)
    val settings = SettingsRepository(app)
    val oui = OuiRepository(app)
    val scans = ScanRepository(scope, scanner, oui)
}

class WifiAnalyzerApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        container.scope.launch { container.oui.loadCached() }
    }
}
