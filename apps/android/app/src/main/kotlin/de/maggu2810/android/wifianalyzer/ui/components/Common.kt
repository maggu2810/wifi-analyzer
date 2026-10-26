// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import de.maggu2810.android.wifianalyzer.R
import de.maggu2810.android.wifianalyzer.ui.theme.SignalColors

/** Signal quality 0..4 (same thresholds as the CLI). */
fun signalLevel(rssi: Int): Int = when {
    rssi >= -55 -> 4
    rssi >= -67 -> 3
    rssi >= -75 -> 2
    rssi >= -85 -> 1
    else -> 0
}

fun signalColor(rssi: Int): Color = when (signalLevel(rssi)) {
    4 -> SignalColors.excellent
    3 -> SignalColors.good
    2 -> SignalColors.fair
    1 -> SignalColors.poor
    else -> SignalColors.bad
}

@Composable
fun SignalBars(rssi: Int, modifier: Modifier = Modifier, stale: Boolean = false) {
    val level = signalLevel(rssi)
    val active = if (stale) MaterialTheme.colorScheme.outline else signalColor(rssi)
    val inactive = MaterialTheme.colorScheme.surfaceVariant
    Canvas(modifier = modifier.size(width = 22.dp, height = 18.dp)) {
        val barWidth = size.width / 5f
        for (i in 0 until 4) {
            val h = size.height * (i + 1) / 4f
            drawRoundRect(
                color = if (i < level) active else inactive,
                topLeft = Offset(i * barWidth * 1.3f, size.height - h),
                size = Size(barWidth, h),
                cornerRadius = CornerRadius(2f, 2f),
            )
        }
    }
}

@Composable
fun SignalIndicator(rssi: Int, modifier: Modifier = Modifier, stale: Boolean = false) {
    Column(modifier = modifier.width(56.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        SignalBars(rssi, stale = stale)
        Text(
            stringResource(R.string.unit_dbm, rssi),
            style = MaterialTheme.typography.labelMedium,
            color = if (stale) MaterialTheme.colorScheme.outline else signalColor(rssi),
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
fun InfoChip(text: String, modifier: Modifier = Modifier, warning: Boolean = false, emphasis: Boolean = false) {
    val colors = MaterialTheme.colorScheme
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(6.dp),
        color = when {
            warning -> colors.errorContainer
            emphasis -> colors.primaryContainer
            else -> colors.surfaceVariant
        },
        contentColor = when {
            warning -> colors.onErrorContainer
            emphasis -> colors.onPrimaryContainer
            else -> colors.onSurfaceVariant
        },
    ) {
        Text(text, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp), style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
fun SectionCard(title: String?, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (title != null) {
                Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            }
            content()
        }
    }
}

@Composable
fun KeyValueRow(label: String, value: String, modifier: Modifier = Modifier, warning: Boolean = false, mono: Boolean = false) {
    Row(modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, Modifier.weight(0.45f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            Modifier.weight(0.55f),
            style = MaterialTheme.typography.bodyMedium,
            color = if (warning) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            fontFamily = if (mono) FontFamily.Monospace else null,
        )
    }
}

@Composable
fun bandLabel(band: String?): String = when (band) {
    null -> stringResource(R.string.unknown)
    else -> stringResource(R.string.band_ghz, band)
}

@Composable
fun formatAge(ageMs: Long): String = when {
    ageMs < 60_000 -> stringResource(R.string.age_seconds, (ageMs / 1000).coerceAtLeast(0))
    ageMs < 3_600_000 -> stringResource(R.string.age_minutes, ageMs / 60_000)
    else -> stringResource(R.string.age_hours, ageMs / 3_600_000)
}

@Composable
fun yesNo(value: Boolean?): String = when (value) {
    null -> stringResource(R.string.not_available)
    true -> stringResource(R.string.yes)
    false -> stringResource(R.string.no)
}
