// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val LightColors = lightColorScheme(primary = Color(0xFF0B5CAD), secondary = Color(0xFF00796B))
private val DarkColors = darkColorScheme(primary = Color(0xFF9CC9FF), secondary = Color(0xFF80CBC4))

/** Signal quality colors (independent of the dynamic scheme for consistency). */
object SignalColors {
    val excellent = Color(0xFF2E7D32)
    val good = Color(0xFF7CB342)
    val fair = Color(0xFFF9A825)
    val poor = Color(0xFFE65100)
    val bad = Color(0xFFC62828)
}

/** Distinct series colors for charts. */
val ChartPalette = listOf(
    Color(0xFF1E88E5), Color(0xFFE53935), Color(0xFF43A047), Color(0xFFFB8C00),
    Color(0xFF8E24AA), Color(0xFF00ACC1), Color(0xFFD81B60), Color(0xFF6D4C41),
    Color(0xFF3949AB), Color(0xFF7CB342), Color(0xFFFDD835), Color(0xFF546E7A),
)

@Composable
fun WifiAnalyzerTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && dark -> dynamicDarkColorScheme(context)
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> dynamicLightColorScheme(context)
        dark -> DarkColors
        else -> LightColors
    }
    MaterialTheme(colorScheme = colors, content = content)
}
