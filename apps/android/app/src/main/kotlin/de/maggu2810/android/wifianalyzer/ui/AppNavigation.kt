// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ShowChart
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.ui.channels.ChannelsScreen
import de.maggu2810.android.wifianalyzer.ui.connection.ConnectionScreen
import de.maggu2810.android.wifianalyzer.ui.detail.DetailScreen
import de.maggu2810.android.wifianalyzer.ui.networks.NetworksScreen
import de.maggu2810.android.wifianalyzer.ui.settings.SettingsScreen
import de.maggu2810.android.wifianalyzer.ui.signal.SignalScreen

private data class Tab(val route: String, val label: Int, val icon: ImageVector)

private val tabs = listOf(
    Tab("networks", R.string.tab_networks, Icons.Filled.Wifi),
    Tab("channels", R.string.tab_channels, Icons.Filled.BarChart),
    Tab("signal", R.string.tab_signal, Icons.AutoMirrored.Filled.ShowChart),
    Tab("connection", R.string.tab_connection, Icons.Filled.Link),
)

@Composable
fun AppNavigation(vm: AppViewModel) {
    val nav = rememberNavController()
    val snackbar = remember { SnackbarHostState() }
    val resources = LocalResources.current
    LaunchedEffect(resources) {
        vm.messages.collect { m -> snackbar.showSnackbar(resources.getString(m.text, *m.args.toTypedArray())) }
    }
    val entry by nav.currentBackStackEntryAsState()
    val route = entry?.destination?.route
    val showTabs = tabs.any { it.route == route }

    val openDetail: (String) -> Unit = { bssid -> nav.navigate("detail/$bssid") }
    val openSettings: () -> Unit = { nav.navigate("settings") }

    PermissionGate(vm) {
        Scaffold(
            contentWindowInsets = WindowInsets(0),
            snackbarHost = { SnackbarHost(snackbar) },
            bottomBar = {
                if (showTabs) {
                    NavigationBar {
                        tabs.forEach { tab ->
                            NavigationBarItem(
                                selected = route == tab.route,
                                onClick = {
                                    nav.navigate(tab.route) {
                                        popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                                        launchSingleTop = true
                                        restoreState = true
                                    }
                                },
                                icon = { Icon(tab.icon, contentDescription = null) },
                                label = { Text(stringResource(tab.label)) },
                            )
                        }
                    }
                }
            },
        ) { padding ->
            val inner = if (showTabs) WindowInsets(0) else WindowInsets.navigationBars
            NavHost(nav, startDestination = "networks", modifier = Modifier.padding(padding)) {
                composable("networks") { NetworksScreen(vm, openDetail, openSettings, inner) }
                composable("channels") { ChannelsScreen(vm, openDetail, openSettings, inner) }
                composable("signal") { SignalScreen(vm, openDetail, openSettings, inner) }
                composable("connection") { ConnectionScreen(vm, openDetail, openSettings, inner) }
                composable("settings") { SettingsScreen(vm, onBack = { nav.popBackStack() }) }
                composable(
                    "detail/{bssid}",
                    arguments = listOf(navArgument("bssid") { type = NavType.StringType }),
                ) { e ->
                    DetailScreen(vm, e.arguments?.getString("bssid").orEmpty(), onBack = { nav.popBackStack() })
                }
            }
        }
    }
}
