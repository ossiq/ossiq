import * as d3 from 'd3'
import { TREE_CONFIG } from './config'
import { nodeKey } from './transform'
import type { D3NodeData, TreeNode, HighlightState } from '@/types/dependency-tree'

export interface TreeLinkRenderOptions {
  g: d3.Selection<SVGGElement, unknown, null, undefined>
  links: d3.HierarchyLink<D3NodeData>[]
  source: TreeNode
  onLinkClick: (node: TreeNode) => void
}

const linkPath = d3
  .linkHorizontal<d3.HierarchyLink<D3NodeData>, d3.HierarchyPointNode<D3NodeData>>()
  .x((d) => d.y)
  .y((d) => d.x) as unknown as string

/**
 * Renders tree edges (solid paths between parent and child nodes) using D3 enter/update/exit.
 * Also renders a wider transparent `.link-hit` overlay on each edge for easier clicking.
 * Handles animated transitions when tree structure changes (new branches, collapsed nodes).
 *
 * Call `applyTreeLinkStyles` after this to apply the current highlight state.
 */
export function renderTreeLinks({ g, links, source, onLinkClick }: TreeLinkRenderOptions) {
  const collapsePoint = () => {
    const o = { x: source.x0 ?? 0, y: source.y0 ?? 0 }
    return d3
      .linkHorizontal<unknown, { x: number; y: number }>()
      .x((p) => p.y)
      .y((p) => p.x)({ source: o, target: o })
  }

  const exitPoint = () => {
    const o = { x: source.x, y: source.y }
    return d3
      .linkHorizontal<unknown, { x: number; y: number }>()
      .x((p) => p.y)
      .y((p) => p.x)({ source: o, target: o })
  }

  // Visual link paths
  const link = g
    .selectAll<SVGPathElement, d3.HierarchyLink<D3NodeData>>('.link')
    .data(links, (d) => nodeKey(d.target))

  const linkEnter = link.enter().insert('path', 'g').attr('class', 'link').attr('d', collapsePoint)

  linkEnter
    .merge(link)
    .transition()
    .duration(TREE_CONFIG.animation.linkTransition)
    .attr('d', linkPath)

  link
    .exit()
    .transition()
    .duration(TREE_CONFIG.animation.linkTransition)
    .attr('d', exitPoint)
    .remove()

  // Transparent hit target overlay (12px wide) for easier edge clicking
  const linkHit = g
    .selectAll<SVGPathElement, d3.HierarchyLink<D3NodeData>>('.link-hit')
    .data(links, (d) => nodeKey(d.target))

  const linkHitEnter = linkHit
    .enter()
    .insert('path', 'g')
    .attr('class', 'link-hit')
    .attr('fill', 'none')
    .attr('stroke', 'transparent')
    .attr('stroke-width', 12)
    .style('cursor', 'pointer')
    .on('click', (event: MouseEvent, d) => {
      event.stopPropagation()
      onLinkClick(d.target as TreeNode)
    })
    .attr('d', collapsePoint)

  linkHitEnter
    .merge(linkHit)
    .transition()
    .duration(TREE_CONFIG.animation.linkTransition)
    .attr('d', linkPath)

  linkHit
    .exit()
    .transition()
    .duration(TREE_CONFIG.animation.linkTransition)
    .attr('d', exitPoint)
    .remove()
}

/** Returns the semantic edge color for a target node in normal (non-focused) state, or null. */
function normalEdgeColor(data: D3NodeData): string | null {
  if (data.severity) return TREE_CONFIG.colors.cvePathLinkStrokeNormal
  const v = data.version_defined?.trim()
  if (v && (v.includes('<') || /^\d[\d.]*$/.test(v))) return TREE_CONFIG.colors.pinnedUbcPathLinkStroke
  return null
}

/** Returns the semantic edge color for an ancestor link in focus mode. */
function ancestorEdgeColor(data: D3NodeData): string {
  if (data.severity) return TREE_CONFIG.colors.cvePathLinkStroke
  const v = data.version_defined?.trim()
  if (v && (v.includes('<') || /^\d[\d.]*$/.test(v))) return TREE_CONFIG.colors.pinnedUbcPathLinkStroke
  return TREE_CONFIG.colors.ancestorLinkStroke
}

/** Returns the semantic edge color for a descendant link in focus mode. */
function descendantEdgeColor(data: D3NodeData): string {
  if (data.severity) return TREE_CONFIG.colors.cvePathLinkStroke
  const v = data.version_defined?.trim()
  if (v && (v.includes('<') || /^\d[\d.]*$/.test(v))) return TREE_CONFIG.colors.pinnedUbcPathLinkStroke
  return TREE_CONFIG.colors.descendantLinkStroke
}

/**
 * Re-applies highlight styles to existing tree link elements without structural changes.
 * Call this after any highlight state change that does not alter tree structure.
 *
 * Normal state: edges to CVE nodes are light red; edges to pinned/UBC nodes are light orange.
 * Focus state: ancestor path edges are colored per target node's exceptional state (CVE → red,
 * pinned/UBC → orange, default → blue); descendant path edges use green/red/orange similarly.
 */
export function applyTreeLinkStyles(
  g: d3.Selection<SVGGElement, unknown, null, undefined>,
  highlight: HighlightState,
) {
  // Use .style() not .attr() — Vue's :deep(.link) CSS properties override presentation attributes.
  // Inline styles (set via .style()) take precedence over CSS rules; null removes the override.
  g.selectAll<SVGPathElement, d3.HierarchyLink<D3NodeData>>('.link')
    .style('stroke', (d) => {
      if (highlight.mode !== 'none') {
        const tk = nodeKey(d.target)
        if (highlight.treeLinkTargetKeys.has(tk)) return ancestorEdgeColor(d.target.data)
        if (highlight.descendantLinkTargetKeys.has(tk)) return descendantEdgeColor(d.target.data)
        return null
      }
      return normalEdgeColor(d.target.data)
    })
    .style('stroke-width', (d) => {
      if (highlight.mode !== 'none') {
        const tk = nodeKey(d.target)
        if (highlight.treeLinkTargetKeys.has(tk) || highlight.descendantLinkTargetKeys.has(tk)) return '3px'
      }
      return null
    })
    .style('opacity', (d) => {
      if (highlight.mode === 'none') return null
      const tk = nodeKey(d.target)
      return highlight.treeLinkTargetKeys.has(tk) || highlight.descendantLinkTargetKeys.has(tk) ? '1' : '0.15'
    })
}
