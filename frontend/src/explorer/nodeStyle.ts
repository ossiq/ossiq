import { TREE_CONFIG } from './config'
import { nodeKey } from './transform'
import type { D3NodeData, TreeNode, NodeStyle, HighlightState } from '@/types/dependency-tree'

export type NodeColorRule = {
  /** Return true if this rule applies to the given node data. Rules are evaluated first-match-wins. */
  test: (data: D3NodeData) => boolean
  fill: string
  stroke: string
}

export function isPinned(v?: string): boolean {
  if (!v) return false
  return /^\d[\d.]*$/.test(v.trim())
}

export function hasUpperConstraint(v?: string): boolean {
  if (!v) return false
  return v.includes('<')
}

/**
 * Ordered color rules for nodes. Add a new entry here to introduce a new node color category.
 * The first rule whose `test` returns true wins — put more specific rules before general ones.
 */
export const NODE_COLOR_RULES: NodeColorRule[] = [
  {
    test: (data) => !!data.severity,
    fill: TREE_CONFIG.colors.cveFill,
    stroke: TREE_CONFIG.colors.cveStroke,
  },
  {
    test: (data) => isPinned(data.version_defined),
    fill: TREE_CONFIG.colors.pinnedFill,
    stroke: TREE_CONFIG.colors.pinnedStroke,
  },
  {
    test: (data) => hasUpperConstraint(data.version_defined),
    fill: TREE_CONFIG.colors.ubcFill,
    stroke: TREE_CONFIG.colors.ubcStroke,
  },
  {
    test: () => true,
    fill: TREE_CONFIG.colors.defaultFill,
    stroke: TREE_CONFIG.colors.defaultStroke,
  },
]

function resolveBaseColors(data: D3NodeData): { fill: string; stroke: string } {
  for (const rule of NODE_COLOR_RULES) {
    if (rule.test(data)) return { fill: rule.fill, stroke: rule.stroke }
  }
  return { fill: TREE_CONFIG.colors.defaultFill, stroke: TREE_CONFIG.colors.defaultStroke }
}

/**
 * Computes the full visual style for a node given its current state and the active highlight state.
 * This is the single source of truth for node appearance — both initial render and re-style calls
 * go through this function.
 */
export function resolveNodeStyle(node: TreeNode, highlight: HighlightState): NodeStyle {
  const k = nodeKey(node)
  const { fill: baseFill, stroke: baseStroke } = resolveBaseColors(node.data)
  const isCollapsed = !!node._children

  const opacity =
    highlight.mode === 'none' ||
    highlight.primaryKeys.has(k) ||
    highlight.secondaryKeys.has(k) ||
    highlight.ancestorKeys.has(k) ||
    highlight.descendantKeys.has(k)
      ? 1
      : TREE_CONFIG.node.opacityDimmed

  let fill: string
  let stroke: string
  let strokeWidth: number

  if (highlight.primaryKeys.has(k)) {
    fill = baseStroke
    stroke = baseStroke
    strokeWidth = TREE_CONFIG.node.strokeWidthHighlighted
  } else if (highlight.secondaryKeys.has(k)) {
    fill = baseStroke
    stroke = baseStroke
    strokeWidth = TREE_CONFIG.node.strokeWidthHighlighted
  } else {
    fill = isCollapsed ? baseStroke : baseFill
    stroke = baseStroke
    strokeWidth = TREE_CONFIG.node.strokeWidth
  }

  return {
    fill,
    stroke,
    strokeWidth,
    opacity,
    radius: isCollapsed ? TREE_CONFIG.node.radiusCollapsed : TREE_CONFIG.node.radiusDefault,
  }
}
