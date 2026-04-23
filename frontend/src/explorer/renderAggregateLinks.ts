import * as d3 from 'd3'
import { TREE_CONFIG } from './config'
import { nodeKey } from './transform'
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
 * a hidden dependency. When multiple folded nodes all point to the same target, they are
 * merged into a single thicker "bundle arc" with an (N) source-count badge.
 *
 * Full teardown-rebuild on each call (aggregate topology changes with every expand/filter).
 */
export function renderAggregateLinks({ g, aggregateEdges, nodesByKey, onLinkClick }: AggregateLinkRenderOptions) {
  g.selectAll('.link-aggregate, .link-aggregate-hit, .link-aggregate-count').remove()

  const cfg = TREE_CONFIG.aggregateLink

  // Group edges by targetKey — single-source arcs render individually; multi-source → bundle
  const byTarget = new Map<string, { sources: TreeNode[]; target: TreeNode }>()
  for (const edge of aggregateEdges) {
    const source = nodesByKey.get(edge.sourceKey)
    const target = nodesByKey.get(edge.targetKey)
    if (!source || !target) continue
    const existing = byTarget.get(edge.targetKey)
    if (existing) {
      existing.sources.push(source)
    } else {
      byTarget.set(edge.targetKey, { sources: [source], target })
    }
  }

  for (const { sources, target } of byTarget.values()) {
    if (sources.length === 1) {
      renderSingleArc(g, sources[0], target, cfg, onLinkClick)
    } else {
      renderBundleArc(g, sources, target, cfg, onLinkClick)
    }
  }
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

function renderSingleArc(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  source: TreeNode,
  target: TreeNode,
  cfg: typeof TREE_CONFIG.aggregateLink,
  onLinkClick: (node: TreeNode) => void,
) {
  const { path } = arcPath(source.y, source.x, target.y, target.x, cfg.bezierOffset)
  const sourceKey = nodeKey(source)

  g.insert('path', '.node')
    .attr('class', 'link-aggregate')
    .attr('data-source-key', sourceKey)
    .attr('fill', 'none')
    .attr('stroke', TREE_CONFIG.colors.dashedLinkDefault)
    .attr('stroke-width', cfg.strokeWidth)
    .attr('stroke-dasharray', cfg.strokeDash)
    .attr('opacity', cfg.opacityNormal)
    .attr('pointer-events', 'none')
    .attr('d', path)

  g.insert('path', '.node')
    .attr('class', 'link-aggregate-hit')
    .attr('data-source-key', sourceKey)
    .attr('fill', 'none')
    .attr('stroke', 'transparent')
    .attr('stroke-width', cfg.hitTargetWidth)
    .attr('d', path)
    .style('cursor', 'pointer')
    .on('click', (event: MouseEvent) => {
      event.stopPropagation()
      onLinkClick(source) // navigate to the visible dep (source)
    })
}

function renderBundleArc(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  sources: TreeNode[],
  target: TreeNode,
  cfg: typeof TREE_CONFIG.aggregateLink,
  onLinkClick: (node: TreeNode) => void,
) {
  // Centroid of all source node positions (SVG convention: node.y = horizontal, node.x = vertical)
  const avgSx = sources.reduce((sum, s) => sum + s.y, 0) / sources.length
  const avgSy = sources.reduce((sum, s) => sum + s.x, 0) / sources.length
  const { path, midX, midY } = arcPath(avgSx, avgSy, target.y, target.x, cfg.bezierOffset)
  const sourceKeysAttr = sources.map((s) => nodeKey(s)).join(',')

  g.insert('path', '.node')
    .attr('class', 'link-aggregate')
    .attr('data-source-keys', sourceKeysAttr)
    .attr('fill', 'none')
    .attr('stroke', TREE_CONFIG.colors.dashedLinkDefault)
    .attr('stroke-width', cfg.strokeWidth)
    .attr('stroke-dasharray', cfg.strokeDash)
    .attr('opacity', cfg.opacityNormal)
    .attr('pointer-events', 'none')
    .attr('d', path)

  g.insert('path', '.node')
    .attr('class', 'link-aggregate-hit')
    .attr('data-source-keys', sourceKeysAttr)
    .attr('fill', 'none')
    .attr('stroke', 'transparent')
    .attr('stroke-width', cfg.hitTargetWidth)
    .attr('d', path)
    .style('cursor', 'pointer')
    .on('click', (event: MouseEvent) => {
      event.stopPropagation()
      onLinkClick(sources[0]!) // focus first visible dep source (same as same-version link)
    })

  // Source-count badge at the arc midpoint
  g.insert('text', '.node')
    .attr('class', 'link-aggregate-count')
    .attr('x', midX)
    .attr('y', midY)
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'middle')
    .attr('font-size', cfg.bundleBadgeFontSize)
    .attr('fill', TREE_CONFIG.colors.dashedLinkDefault)
    .attr('pointer-events', 'none')
    .text(`(${sources.length})`)
}

/**
 * Highlights aggregate arcs whose source node is currently focused, mirroring
 * applySameVersionLinkStyles: orange stroke + 3px width when relevant, dim when not.
 */
export function applyAggregateLinkStyles(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  highlight: HighlightState,
) {
  function isRelevant(el: Element): boolean {
    const multi = el.getAttribute('data-source-keys')
    const single = el.getAttribute('data-source-key')
    const keys = multi ? multi.split(',') : single ? [single] : []
    return keys.some((k) => highlight.primaryKeys.has(k) || highlight.secondaryKeys.has(k))
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
