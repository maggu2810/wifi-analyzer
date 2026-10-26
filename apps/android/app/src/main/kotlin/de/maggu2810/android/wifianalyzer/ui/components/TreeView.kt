// SPDX-License-Identifier: MIT
package de.maggu2810.android.wifianalyzer.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import de.maggu2810.android.wifianalyzer.nativelib.TreeNode

/** A tree node with its depth, for flat (lazy) rendering. */
data class FlatNode(val node: TreeNode, val depth: Int, val id: String)

/** Depth-first flattening; detail nodes are skipped unless [showDetail]. */
fun flatten(nodes: List<TreeNode>, showDetail: Boolean, depth: Int = 0, prefix: String = ""): List<FlatNode> {
    val out = ArrayList<FlatNode>()
    nodes.forEachIndexed { i, n ->
        if (n.isDetail && !showDetail) return@forEachIndexed
        val id = "$prefix/$i"
        out += FlatNode(n, depth, id)
        out += flatten(n.children, showDetail, depth + 1, id)
    }
    return out
}

/**
 * One row of a decoded tree: label left, library-formatted value right. Group nodes (no value)
 * are emphasized, list entries rendered as bullets, warnings in the error color.
 */
@Composable
fun TreeRow(flat: FlatNode, selected: Boolean, onClick: (() -> Unit)?, modifier: Modifier = Modifier) {
    val n = flat.node
    val colors = MaterialTheme.colorScheme
    val clickable = if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier
    Row(
        modifier
            .fillMaxWidth()
            .background(if (selected) colors.secondaryContainer else colors.surface.copy(alpha = 0f))
            .then(clickable)
            .padding(start = (8 + 14 * flat.depth).dp, end = 8.dp, top = 3.dp, bottom = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val valueColor = if (n.isWarning) colors.error else colors.onSurface
        when {
            n.isListItem -> Text("• ${n.text.orEmpty()}", style = MaterialTheme.typography.bodyMedium, color = valueColor)
            n.text == null -> Text(
                n.label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = if (n.isWarning) colors.error else colors.primary,
            )
            else -> {
                Text(
                    n.label,
                    Modifier.weight(0.55f),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (n.isDetail) colors.outline else colors.onSurfaceVariant,
                )
                Text(
                    n.text.orEmpty(),
                    Modifier.weight(0.45f),
                    style = MaterialTheme.typography.bodyMedium,
                    color = valueColor,
                    fontWeight = if (n.isWarning) FontWeight.SemiBold else null,
                    textAlign = TextAlign.End,
                )
            }
        }
    }
}
