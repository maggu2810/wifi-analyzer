// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.WifiFind
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import de.maggu2810.android.wifianalyzer.R

/** Permissions needed for scan results (fine location on all versions, nearby devices on 13+). */
fun requiredPermissions(): Array<String> =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.NEARBY_WIFI_DEVICES)
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

/** Shows an explanation until the scan permissions are granted, then [content]. */
@Composable
fun PermissionGate(vm: AppViewModel, content: @Composable () -> Unit) {
    val context = LocalContext.current
    var check by remember { mutableIntStateOf(0) }
    var requested by remember { mutableIntStateOf(0) }
    val granted = remember(check) {
        requiredPermissions().all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        requested++
        check++
    }
    LifecycleResumeEffect(Unit) {
        check++
        onPauseOrDispose { }
    }
    LaunchedEffect(granted) {
        if (granted) vm.onPermissionsGranted()
    }
    if (granted) {
        content()
        return
    }
    Surface(Modifier.fillMaxSize()) {
        Column(
            Modifier.safeDrawingPadding().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(Icons.Filled.WifiFind, contentDescription = null, Modifier.size(72.dp), tint = MaterialTheme.colorScheme.primary)
            Text(stringResource(R.string.permission_title), style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.permission_text), style = MaterialTheme.typography.bodyLarge)
            Button(onClick = { launcher.launch(requiredPermissions()) }) {
                Text(stringResource(R.string.permission_grant))
            }
            if (requested > 0) {
                OutlinedButton(onClick = {
                    context.startActivity(
                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)),
                    )
                }) {
                    Text(stringResource(R.string.permission_open_settings))
                }
            }
        }
    }
}
