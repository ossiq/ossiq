import * as d3 from 'd3'
import { TREE_CONFIG } from './config'
import { nodeKey } from './transform'
import type { TreeNode, NodeStyle, HighlightState } from '@/types/dependency-tree'

export interface NodeRenderOptions {
  g: d3.Selection<SVGGElement, unknown, null, undefined>
  nodes: TreeNode[]
  source: TreeNode
  onNodeClick: (event: MouseEvent, d: TreeNode) => void
}

/**
 * Renders tree nodes (circles, labels, CVE indicators) using D3 enter/update/exit.
 * Handles animated transitions when nodes are added, removed, or moved.
 *
 * Does not apply visual styles — call `applyNodeStyles` after to apply fill/stroke/opacity.
 */
export function renderNodes({ g, nodes, source, onNodeClick }: NodeRenderOptions) {
  const node = g.selectAll<SVGGElement, TreeNode>('.node').data(nodes, nodeKey)

  const nodeEnter = node
    .enter()
    .append('g')
    .attr('class', (d) => `node${d._children ? ' collapsed' : ''}`)
    .attr('transform', () => `translate(${source.y0 ?? 0},${source.x0 ?? 0})`)
    .on('click', onNodeClick)

  // Circle
  nodeEnter
    .append('circle')
    .attr('r', TREE_CONFIG.node.radiusDefault)
    .attr('fill', TREE_CONFIG.colors.defaultFill)
    .attr('stroke', TREE_CONFIG.colors.defaultStroke)
    .attr('stroke-width', TREE_CONFIG.node.strokeWidth)

  // Package name label (above the circle)
  nodeEnter
    .append('text')
    .attr('dy', '-0.6em')
    .attr('x', 12)
    .text((d) => d.data.name)
    .attr('class', 'node-label')

  // Installed version label (below the circle)
  nodeEnter
    .append('text')
    .attr('dy', '1.1em')
    .attr('x', 12)
    .text((d) => `v${d.data.version_installed}`)
    .attr('class', 'version-label')

  // CVE warning triangle — only rendered when a severity is present
  const cveGroup = nodeEnter
    .filter((d) => !!d.data.severity)
    .append('g')
    .attr('class', 'cve-indicator')
    .attr('transform', 'translate(-22, 0)')

  cveGroup
    .append('polygon')
    .attr('points', '0,-9 8,5 -8,5')
    .attr('fill', TREE_CONFIG.colors.cveIndicatorFill)
    .attr('stroke', TREE_CONFIG.colors.cveIndicatorStroke)
    .attr('stroke-width', 1.5)

  cveGroup
    .append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '4px')
    .attr('font-size', '9px')
    .attr('font-weight', 'bold')
    .attr('fill', TREE_CONFIG.colors.cveIndicatorText)
    .text('!')

  // Transition all nodes to their computed positions
  nodeEnter
    .merge(node)
    .transition()
    .duration(TREE_CONFIG.animation.nodeTransition)
    .attr('transform', (d) => `translate(${d.y},${d.x})`)

  node
    .exit()
    .transition()
    .duration(TREE_CONFIG.animation.nodeTransition)
    .attr('transform', () => `translate(${source.y},${source.x})`)
    .remove()
}

/**
 * Re-applies visual styles (fill, stroke, opacity, radius) to all existing node elements.
 * Call this after any highlight state change or after `renderNodes` completes.
 *
 * The `resolveStyle` callback is the single source of truth for node appearance — pass
 * `resolveNodeStyle` from `nodeStyle.ts`, or a custom override for testing/theming.
 */
export function applyNodeStyles(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  highlight: HighlightState,
  resolveStyle: (node: TreeNode, hl: HighlightState) => NodeStyle,
) {
  const nodeGroups = g.selectAll<SVGGElement, TreeNode>('.node')
  nodeGroups.attr('opacity', (d) => resolveStyle(d, highlight).opacity)
  nodeGroups
    .select<SVGCircleElement>('circle')
    .attr('fill', (d) => resolveStyle(d, highlight).fill)
    .attr('stroke', (d) => resolveStyle(d, highlight).stroke)
    .attr('stroke-width', (d) => resolveStyle(d, highlight).strokeWidth)
    .attr('stroke-dasharray', (d) => resolveStyle(d, highlight).strokeDash)
    .attr('r', (d) => resolveStyle(d, highlight).radius)
}
