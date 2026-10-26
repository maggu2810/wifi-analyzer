// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import de.maggu2810.android.wifianalyzer.domain.SignalSample

private const val RSSI_TOP = -20f
private const val RSSI_BOTTOM = -100f

/** One AP in the channel graph. */
data class ChannelSpan(
    val label: String,
    /** Center frequencies (one, or two for 80+80). */
    val centersMhz: List<Int>,
    /** Width of each segment. */
    val segmentWidthMhz: Int,
    val rssi: Int,
    val color: Color,
    val highlighted: Boolean = false,
)

private data class BandAxis(val startMhz: Int, val endMhz: Int, val ticks: List<Pair<Int, String>>, val dpPerMhz: Float?)

private fun axisFor(band: String): BandAxis = when (band) {
    "2.4" -> BandAxis(2400, 2495, (1..13).map { (2407 + 5 * it) to it.toString() } + (2484 to "14"), null)
    "5" -> BandAxis(5150, 5895, (36..177 step 4).map { (5000 + 5 * it) to it.toString() }, 3.2f)
    "6" -> BandAxis(5925, 7125, (1..233 step 4).map { (5950 + 5 * it) to it.toString() }, 2.2f)
    else -> BandAxis(5150, 5895, emptyList(), 3.2f)
}

private fun DrawScope.rssiY(rssi: Float, top: Float, bottom: Float): Float =
    top + (bottom - top) * ((RSSI_TOP - rssi.coerceIn(RSSI_BOTTOM, RSSI_TOP)) / (RSSI_TOP - RSSI_BOTTOM))

private fun DrawScope.rssiGrid(measurer: TextMeasurer, color: Color, top: Float, bottom: Float, left: Float) {
    for (level in listOf(-30, -50, -70, -90)) {
        val y = rssiY(level.toFloat(), top, bottom)
        drawLine(color.copy(alpha = 0.3f), Offset(left, y), Offset(size.width, y), pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 6f)))
        drawText(measurer, level.toString(), Offset(2f, y - 14f), TextStyle(fontSize = 10.sp, color = color))
    }
}

/**
 * Channel graph: each AP is drawn as a trapezoid spanning its occupied bandwidth with the
 * height of its signal strength. 5 and 6 GHz scroll horizontally.
 */
@Composable
fun ChannelGraph(spans: List<ChannelSpan>, band: String, modifier: Modifier = Modifier, onTap: (Int) -> Unit = {}) {
    val axis = axisFor(band)
    val measurer = rememberTextMeasurer()
    val outline = MaterialTheme.colorScheme.outline
    val onSurface = MaterialTheme.colorScheme.onSurface
    BoxWithConstraints(modifier) {
        val available = this.maxWidth
        val scroll = rememberScrollState()
        val contentWidth = axis.dpPerMhz?.let { ((axis.endMhz - axis.startMhz) * it).dp } ?: available
        Box(Modifier.horizontalScroll(scroll)) {
            Canvas(
                Modifier
                    .width(maxOf(contentWidth, available))
                    .fillMaxHeight()
                    .pointerInput(spans, band) {
                        detectTapGestures { pos ->
                            val mhz = axis.startMhz + (pos.x - 40f) / (size.width - 48f) * (axis.endMhz - axis.startMhz)
                            val hit = spans.indices.filter { i ->
                                spans[i].centersMhz.any { c -> kotlin.math.abs(mhz - c) <= spans[i].segmentWidthMhz / 2f }
                            }.maxByOrNull { spans[it].rssi }
                            if (hit != null) onTap(hit)
                        }
                    },
            ) {
                val left = 40f
                val right = size.width - 8f
                val top = 20f
                val bottom = size.height - 28f
                fun x(mhz: Float) = left + (mhz - axis.startMhz) / (axis.endMhz - axis.startMhz) * (right - left)

                rssiGrid(measurer, outline, top, bottom, left)
                drawLine(outline, Offset(left, bottom), Offset(right, bottom))
                var lastLabelX = -1000f
                for ((mhz, label) in axis.ticks) {
                    val tx = x(mhz.toFloat())
                    drawLine(outline, Offset(tx, bottom), Offset(tx, bottom + 5f))
                    if (tx - lastLabelX > 26f) {
                        drawText(measurer, label, Offset(tx - 8f, bottom + 6f), TextStyle(fontSize = 10.sp, color = outline))
                        lastLabelX = tx
                    }
                }
                // Weakest first so strong APs are on top.
                for (span in spans.sortedBy { if (it.highlighted) Int.MAX_VALUE else it.rssi }) {
                    val peak = rssiY(span.rssi.toFloat(), top, bottom)
                    for (center in span.centersMhz) {
                        val half = span.segmentWidthMhz / 2f
                        val slope = minOf(4f, half / 4f)
                        val path = Path().apply {
                            moveTo(x(center - half), bottom)
                            lineTo(x(center - half + slope), peak)
                            lineTo(x(center + half - slope), peak)
                            lineTo(x(center + half), bottom)
                        }
                        drawPath(path, span.color.copy(alpha = if (span.highlighted) 0.35f else 0.15f))
                        drawPath(path, span.color, style = Stroke(width = if (span.highlighted) 5f else 2.5f))
                        drawText(
                            measurer,
                            span.label,
                            Offset(x(center.toFloat()) - 24f, peak - 16f),
                            TextStyle(fontSize = 10.sp, color = if (span.highlighted) span.color else onSurface),
                        )
                    }
                }
            }
        }
    }
}

data class SignalSeries(val label: String, val color: Color, val samples: List<SignalSample>)

/** RSSI over time for several BSSs within [windowMs] before [nowMs]. */
@Composable
fun SignalChart(series: List<SignalSeries>, nowMs: Long, windowMs: Long, modifier: Modifier = Modifier) {
    val measurer = rememberTextMeasurer()
    val outline = MaterialTheme.colorScheme.outline
    Canvas(modifier.fillMaxWidth().height(260.dp)) {
        val left = 40f
        val right = size.width - 8f
        val top = 12f
        val bottom = size.height - 24f
        fun x(t: Long) = left + (1f - (nowMs - t).toFloat() / windowMs) * (right - left)

        rssiGrid(measurer, outline, top, bottom, left)
        drawLine(outline, Offset(left, bottom), Offset(right, bottom))
        val minutes = (windowMs / 60_000).toInt().coerceAtLeast(1)
        val step = if (minutes > 10) 5 else 1
        for (m in 0..minutes step step) {
            val tx = x(nowMs - m * 60_000L)
            drawLine(outline.copy(alpha = 0.3f), Offset(tx, top), Offset(tx, bottom))
            drawText(measurer, if (m == 0) "0" else "-${m}m", Offset(tx - 10f, bottom + 4f), TextStyle(fontSize = 10.sp, color = outline))
        }
        for (s in series) {
            val points = s.samples.filter { nowMs - it.timestampMs <= windowMs }
            if (points.isEmpty()) continue
            val path = Path()
            points.forEachIndexed { i, p ->
                val px = x(p.timestampMs)
                val py = rssiY(p.rssiDbm.toFloat(), top, bottom)
                if (i == 0) path.moveTo(px, py) else path.lineTo(px, py)
                drawCircle(s.color, radius = 3f, center = Offset(px, py))
            }
            drawPath(path, s.color, style = Stroke(width = 3f))
        }
    }
}
