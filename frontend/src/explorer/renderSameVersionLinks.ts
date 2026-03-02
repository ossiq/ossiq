import * as d3 from 'd3'
import { TREE_CONFIG } from './config'
import { nodeKey } from './transform'
import type { TreeNode, HighlightState } from '@/types/dependency-tree'

export interface SameVersionLinkRenderOptions {
  g: d3.Selection<SVGGElement, unknown, null, undefined>
  nodes: TreeNode[]
  onLinkClick: (node: TreeNode) => void
}

/**
 * Builds same-version group pairs and renders them as dashed quadratic bezier paths.
 * Also renders a wider transparent hit target over each path to make clicking easier.
 *
 * Always does a full teardown-rebuild (no D3 diff) since pairs change whenever the tree
 * structure changes (branch toggle, new data). Call `applySameVersionLinkStyles` after to
 * apply the current highlight state.
 *
 * To add a new edge type, create a similar render function and call it from useD3Tree.update().
 */
export function renderSameVersionLinks({ g, nodes, onLinkClick }: SameVersionLinkRenderOptions) {
  g.selectAll('.link-same-version, .link-same-version-hit').remove()

  const sameVersionMap = new Map<string, TreeNode[]>()
  nodes.forEach((d) => {
    const key = `${d.data.name}@${d.data.version_installed}`
    if (!sameVersionMap.has(key)) sameVersionMap.set(key, [])
    sameVersionMap.get(key)!.push(d)
  })

  sameVersionMap.forEach((group) => {
    if (group.length < 2) return
    for (let i = 0; i < group.length - 1; i++) {
      const s = group[i]!
      const t = group[i + 1]!
      // SVG coords: x-axis = d.y (horizontal depth), y-axis = d.x (vertical position)
      const sx = s.y, sy = s.x
      const tx = t.y, ty = t.x
      const dx = tx - sx
      const dy = ty - sy
      const len = Math.sqrt(dx * dx + dy * dy) || 1
      // Control point: midpoint + TREE_CONFIG.sameVersionLink.bezierOffset px perpendicular (90° CCW)
      const cx = (sx + tx) / 2 + (-dy / len) * TREE_CONFIG.sameVersionLink.bezierOffset
      const cy = (sy + ty) / 2 + (dx / len) * TREE_CONFIG.sameVersionLink.bezierOffset
      const pathD = `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`
      const pairKey = `${nodeKey(s)}--${nodeKey(t)}`

      // Visual path (dashed, thin — CSS provides default stroke/dasharray/opacity)
      g.insert('path', ':first-child')
        .attr('class', 'link-same-version')
        .attr('data-pair', pairKey)
        .attr('d', pathD)

      // Wide transparent hit target to make the thin path easy to click
      g.insert('path', ':first-child')
        .attr('class', 'link-same-version-hit')
        .attr('data-pair', pairKey)
        .attr('fill', 'none')
        .attr('stroke', 'transparent')
        .attr('stroke-width', TREE_CONFIG.sameVersionLink.hitTargetWidth)
        .attr('d', pathD)
        .style('cursor', 'pointer')
        .on('click', (event: MouseEvent) => {
          event.stopPropagation()
          onLinkClick(s)
        })
    }
  })
}

/**
 * Re-applies highlight styles to existing same-version link elements without rebuilding them.
 * Call this after any highlight state change that does not change tree structure.
 */
export function applySameVersionLinkStyles(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  highlight: HighlightState,
) {
  // Use .style() not .attr() — Vue's :deep(.link-same-version) CSS properties override
  // presentation attributes. Inline styles beat CSS rules; null removes the override.
  g.selectAll<SVGPathElement, unknown>('.link-same-version')
    .style('stroke', function () {
      const pair = (this as SVGPathElement).getAttribute('data-pair') ?? ''
      return highlight.dashedLinkPairs.has(pair)
        ? TREE_CONFIG.colors.dashedLinkDuplicateHighlighted
        : null
    })
    .style('opacity', function () {
      if (highlight.mode === 'none') return null
      const pair = (this as SVGPathElement).getAttribute('data-pair') ?? ''
      return highlight.dashedLinkPairs.has(pair)
        ? String(TREE_CONFIG.sameVersionLink.opacityHighlighted)
        : String(TREE_CONFIG.sameVersionLink.opacityDimmed)
    })
    .style('stroke-width', function () {
      const pair = (this as SVGPathElement).getAttribute('data-pair') ?? ''
      return highlight.dashedLinkPairs.has(pair) ? '3px' : null
    })
}
