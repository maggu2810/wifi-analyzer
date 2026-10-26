// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp

/**
 * Hex dump (8 octets per row) with the octets in [highlight] (offset until offset+length)
 * emphasized. Offsets are relative to [bytes].
 */
@Composable
fun HexView(bytes: ByteArray, highlight: IntRange?, modifier: Modifier = Modifier, perRow: Int = 8) {
    val colors = MaterialTheme.colorScheme
    Column(modifier.padding(8.dp)) {
        for (row in bytes.indices step perRow) {
            val text = buildAnnotatedString {
                withStyle(SpanStyle(color = colors.outline)) { append("%04x  ".format(row)) }
                for (i in row until minOf(row + perRow, bytes.size)) {
                    val hex = "%02x".format(bytes[i])
                    if (highlight != null && i in highlight) {
                        withStyle(SpanStyle(background = colors.tertiaryContainer, color = colors.onTertiaryContainer, fontWeight = FontWeight.Bold)) {
                            append(hex)
                        }
                    } else {
                        append(hex)
                    }
                    append(' ')
                }
            }
            Text(text, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        }
    }
}
