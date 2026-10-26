// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import de.maggu2810.android.wifianalyzer.ui.AppNavigation
import de.maggu2810.android.wifianalyzer.ui.AppViewModel
import de.maggu2810.android.wifianalyzer.ui.theme.WifiAnalyzerTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val viewModel: AppViewModel by viewModels {
        viewModelFactory {
            initializer {
                val app = application as WifiAnalyzerApp
                AppViewModel(app, app.container)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            WifiAnalyzerTheme {
                AppNavigation(viewModel)
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.foregroundLoop()
            }
        }
    }
}
