import * as d3 from 'd3'
import { TREE_CONFIG } from './config'
import type { TreeNode, HighlightState } from '@/types/dependency-tree'
import type { VisibleEdge } from '@/types/registry'

export interface AggregateLinkRenderOptions {
  g: d3.Selection<SVGGElement, unknown, null, undefined>
  aggregateEdges: VisibleEdge[]
  nodesByKey: Map<string, TreeNode>
  onLinkClick: (node: TreeNode) => void
}

/**
 * Renders curved dashed arcs from folded Super Nodes to already-visible nodes that share
 * a hidden dependency. Uses the same quadratic-bezier approach as same-version links.
 * Full teardown-rebuild on each call (aggregate topology changes with every expand/filter).
 */
export function renderAggregateLinks({ g, aggregateEdges, nodesByKey, onLinkClick }: AggregateLinkRenderOptions) {
  g.selectAll('.link-aggregate, .link-aggregate-hit').remove()

  const cfg = TREE_CONFIG.aggregateLink

  for (const edge of aggregateEdges) {
    const source = nodesByKey.get(edge.sourceKey)
    const target = nodesByKey.get(edge.targetKey)
    if (!source || !target) continue

    // SVG coordinate convention: d.y = horizontal position, d.x = vertical position
    const sx = source.y, sy = source.x
    const tx = target.y, ty = target.x
    const dx = tx - sx
    const dy = ty - sy
    const len = Math.sqrt(dx * dx + dy * dy) || 1
    // Perpendicular offset gives a smooth curve that avoids overlapping tree edges
    const cx = (sx + tx) / 2 + (-dy / len) * cfg.bezierOffset
    const cy = (sy + ty) / 2 + (dx / len) * cfg.bezierOffset
    const pathD = `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`
    const pairKey = `${edge.sourceKey}--${edge.targetKey}`

    // Visual path (inserted before .node so nodes render on top)
    g.insert('path', '.node')
      .attr('class', 'link-aggregate')
      .attr('data-pair', pairKey)
      .attr('fill', 'none')
      .attr('stroke', cfg.stroke)
      .attr('stroke-width', cfg.strokeWidth)
      .attr('stroke-dasharray', cfg.strokeDash)
      .attr('opacity', cfg.opacityNormal)
      .attr('pointer-events', 'none')
      .attr('d', pathD)

    // Wide transparent hit target for easier clicking
    g.insert('path', '.node')
      .attr('class', 'link-aggregate-hit')
      .attr('data-pair', pairKey)
      .attr('fill', 'none')
      .attr('stroke', 'transparent')
      .attr('stroke-width', cfg.hitTargetWidth)
      .attr('d', pathD)
      .style('cursor', 'pointer')
      .on('click', (event: MouseEvent) => {
        event.stopPropagation()
        onLinkClick(target)
      })
  }
}

/**
 * Dims all aggregate links uniformly in focus mode.
 * Aggregate links don't participate in the ancestor-path highlight scheme —
 * they convey structural information, not the focused path.
 */
export function applyAggregateLinkStyles(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  highlight: HighlightState,
) {
  g.selectAll<SVGPathElement, unknown>('.link-aggregate').style('opacity', () => {
    if (highlight.mode === 'none') return null
    return String(TREE_CONFIG.aggregateLink.opacityDimmed)
  })
}
