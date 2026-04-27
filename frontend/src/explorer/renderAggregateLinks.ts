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
 * Renders curved dashed arcs from visible dep nodes to the folded super nodes or phantom root
 * that contain them as hidden children.
 *
 * Grouping: edges are grouped by (depth-1 ancestor of sourceKey, targetKey). This collapses
 * multiple transitive-dep arcs (e.g. root>B>G and root>B>H both hidden in root>A>B) into one
 * arc originating at the direct-dep node (root>B) with a count badge showing how many of its
 * descendants are hidden in the target super node.
 *
 * For phantom-root edges the sources are already at depth 1, so each remains an individual arc
 * with a "(1)" badge.
 *
 * Full teardown-rebuild on each call (aggregate topology changes with every expand/filter).
 */
export function renderAggregateLinks({ g, aggregateEdges, nodesByKey, onLinkClick }: AggregateLinkRenderOptions) {
  g.selectAll('.link-aggregate, .link-aggregate-hit, .link-aggregate-count').remove()

  const cfg = TREE_CONFIG.aggregateLink

  // Group by (depth-1 ancestor of source, targetKey) — one arc per direct-dep→supernode pair
  const byGroup = new Map<string, { anchorNode: TreeNode; anchorKey: string; target: TreeNode; count: number }>()
  for (const edge of aggregateEdges) {
    const anchorKey = depth1AncestorKey(edge.sourceKey)
    const anchorNode = nodesByKey.get(anchorKey)
    const target = nodesByKey.get(edge.targetKey)
    if (!anchorNode || !target) continue
    const groupKey = `${anchorKey}|${edge.targetKey}`
    const existing = byGroup.get(groupKey)
    if (existing) {
      existing.count++
    } else {
      byGroup.set(groupKey, { anchorNode, anchorKey, target, count: 1 })
    }
  }

  for (const { anchorNode, anchorKey, target, count } of byGroup.values()) {
    renderArc(g, anchorNode, anchorKey, target, count, cfg, onLinkClick)
  }
}

/** Returns the depth-1 ancestor key (first two path segments), e.g. "root>B" from "root>B>G>X". */
function depth1AncestorKey(sourceKey: string): string {
  const first = sourceKey.indexOf('>')
  if (first === -1) return sourceKey
  const second = sourceKey.indexOf('>', first + 1)
  return second === -1 ? sourceKey : sourceKey.slice(0, second)
}

function arcPath(sx: number, sy: number, tx: number, ty: number, bezierOffset: number): { path: string; midX: number; midY: number } {
  const dx = tx - sx
  const dy = ty - sy
  const len = Math.sqrt(dx * dx + dy * dy) || 1
  const cx = (sx + tx) / 2 + (-dy / len) * bezierOffset
  const cy = (sy + ty) / 2 + (dx / len) * bezierOffset
  // Quadratic bezier midpoint at t=0.5: (P0 + 2*P1 + P2) / 4
  const midX = (sx + 2 * cx + tx) / 4
  const midY = (sy + 2 * cy + ty) / 4
  return { path: `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`, midX, midY }
}

function renderArc(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  anchor: TreeNode,
  anchorKey: string,
  target: TreeNode,
  count: number,
  cfg: typeof TREE_CONFIG.aggregateLink,
  onLinkClick: (node: TreeNode) => void,
) {
  const { path, midX, midY } = arcPath(anchor.y, anchor.x, target.y, target.x, cfg.bezierOffset)
  const isBundle = count > 1

  g.insert('path', '.node')
    .attr('class', 'link-aggregate')
    .attr('data-source-key', anchorKey)
    .attr('fill', 'none')
    .attr('stroke', TREE_CONFIG.colors.dashedLinkDefault)
    .attr('stroke-width', isBundle ? cfg.bundleStrokeWidth : cfg.strokeWidth)
    .attr('stroke-dasharray', isBundle ? cfg.bundleStrokeDash : cfg.strokeDash)
    .attr('opacity', isBundle ? cfg.bundleOpacity : cfg.opacityNormal)
    .attr('pointer-events', 'none')
    .attr('d', path)

  g.insert('path', '.node')
    .attr('class', 'link-aggregate-hit')
    .attr('data-source-key', anchorKey)
    .attr('fill', 'none')
    .attr('stroke', 'transparent')
    .attr('stroke-width', cfg.hitTargetWidth)
    .attr('d', path)
    .style('cursor', 'pointer')
    .on('click', (event: MouseEvent) => {
      event.stopPropagation()
      onLinkClick(anchor)
    })

  g.insert('text', '.node')
    .attr('class', 'link-aggregate-count')
    .attr('x', midX)
    .attr('y', midY)
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'middle')
    .attr('font-size', cfg.bundleBadgeFontSize)
    .attr('fill', TREE_CONFIG.colors.dashedLinkDefault)
    .attr('pointer-events', 'none')
    .text(`(${count})`)
}

/**
 * Highlights aggregate arcs whose anchor (depth-1 source) node is currently focused.
 */
export function applyAggregateLinkStyles(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  highlight: HighlightState,
) {
  function isRelevant(el: Element): boolean {
    const key = el.getAttribute('data-source-key')
    return key !== null && (highlight.primaryKeys.has(key) || highlight.secondaryKeys.has(key))
  }

  g.selectAll<SVGPathElement, unknown>('.link-aggregate')
    .style('stroke', function () {
      if (highlight.mode === 'none') return null
      return isRelevant(this) ? TREE_CONFIG.colors.dashedLinkDuplicateHighlighted : null
    })
    .style('opacity', function () {
      if (highlight.mode === 'none') return null
      return isRelevant(this)
        ? String(TREE_CONFIG.sameVersionLink.opacityHighlighted)
        : String(TREE_CONFIG.sameVersionLink.opacityDimmed)
    })
    .style('stroke-width', function () {
      if (highlight.mode === 'none') return null
      return isRelevant(this) ? '3px' : null
    })
}
