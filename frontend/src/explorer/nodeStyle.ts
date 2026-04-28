import { TREE_CONFIG } from './config'
import { nodeKey } from './transform'
import type { D3NodeData, TreeNode, NodeStyle, HighlightState } from '@/types/dependency-tree'

export type NodeColorRule = {
  /** Return true if this rule applies to the given node data. Rules are evaluated first-match-wins. */
  test: (data: D3NodeData) => boolean
  fill: string
  stroke: string
  /** SVG stroke-dasharray value; empty string means solid. */
  strokeDash?: string
  /** Override the default stroke width for this rule (normal, non-highlighted state). */
  strokeWidthBase?: number
  /** Override the default expanded radius for this rule. */
  radiusBase?: number
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
 *
 * Priority: CVE > OVERRIDE > ADDITIVE > PINNED > NARROWED > default
 * For backwards-compat with pre-v1.2 reports, PINNED and NARROWED fall back to version-string heuristics.
 */
export const NODE_COLOR_RULES: NodeColorRule[] = [
  // CVE — highest visibility
  {
    test: (data) => !!data.severity,
    fill: TREE_CONFIG.colors.cveFill,
    stroke: TREE_CONFIG.colors.cveStroke,
  },
  // OVERRIDE — forced version replacement (fuchsia, thick dash-dot, larger radius)
  {
    test: (data) => data.constraint_type === 'OVERRIDE',
    fill: TREE_CONFIG.colors.overriddenFill,
    stroke: TREE_CONFIG.colors.overriddenStroke,
    strokeDash: '7,2,2,2',
    strokeWidthBase: 3,
    radiusBase: 8,
  },
  // ADDITIVE — external constraint file narrows range (purple, dotted)
  {
    test: (data) => data.constraint_type === 'ADDITIVE',
    fill: TREE_CONFIG.colors.constrainedFill,
    stroke: TREE_CONFIG.colors.constrainedStroke,
    strokeDash: '2,2.5',
  },
  // PINNED — exact version required (yellow, thick solid, slightly larger radius)
  // Falls back to version-string heuristic for pre-v1.2 reports
  {
    test: (data) => data.constraint_type === 'PINNED' || isPinned(data.version_defined),
    fill: TREE_CONFIG.colors.pinnedFill,
    stroke: TREE_CONFIG.colors.pinnedStroke,
    strokeWidthBase: 3,
    radiusBase: 7,
  },
  // NARROWED — bounded range constraint (red, dashed)
  {
    test: (data) => data.constraint_type === 'NARROWED',
    fill: TREE_CONFIG.colors.narrowedFill,
    stroke: TREE_CONFIG.colors.narrowedStroke,
    strokeDash: '5,3',
  },
  // Default / DECLARED
  {
    test: () => true,
    fill: TREE_CONFIG.colors.defaultFill,
    stroke: TREE_CONFIG.colors.defaultStroke,
  },
]

function resolveBaseStyle(data: D3NodeData): {
  fill: string
  stroke: string
  strokeDash: string
  strokeWidthBase: number
  radiusBase: number
} {
  // Folded Super Nodes take visual priority over all semantic color rules
  const hiddenChildCount = data._hiddenChildCount ?? 0
  if (data._isFolded && hiddenChildCount > 0) {
    const tier = hiddenChildCount > 50 ? 'Large' : hiddenChildCount > 10 ? 'Medium' : 'Small'
    const cfg = TREE_CONFIG.foldedNode
    return {
      fill: data._hasChildCve ? TREE_CONFIG.colors.cveFill : cfg[`fill${tier}`],
      stroke: data._hasChildCve ? TREE_CONFIG.colors.cveStroke : cfg[`stroke${tier}`],
      strokeDash: cfg.strokeDash,
      strokeWidthBase: cfg.strokeWidth,
      radiusBase: cfg[`radius${tier}`],
    }
  }
  for (const rule of NODE_COLOR_RULES) {
    if (rule.test(data)) {
      return {
        fill: rule.fill,
        stroke: rule.stroke,
        strokeDash: rule.strokeDash ?? '',
        strokeWidthBase: rule.strokeWidthBase ?? TREE_CONFIG.node.strokeWidth,
        radiusBase: rule.radiusBase ?? TREE_CONFIG.node.radiusDefault,
      }
    }
  }
  return {
    fill: TREE_CONFIG.colors.defaultFill,
    stroke: TREE_CONFIG.colors.defaultStroke,
    strokeDash: '',
    strokeWidthBase: TREE_CONFIG.node.strokeWidth,
    radiusBase: TREE_CONFIG.node.radiusDefault,
  }
}

/**
 * Computes the full visual style for a node given its current state and the active highlight state.
 * This is the single source of truth for node appearance — both initial render and re-style calls
 * go through this function.
 */
export function resolveNodeStyle(node: TreeNode, highlight: HighlightState): NodeStyle {
  const k = nodeKey(node)
  const { fill: baseFill, stroke: baseStroke, strokeDash, strokeWidthBase, radiusBase } = resolveBaseStyle(node.data)
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
    strokeWidth = strokeWidthBase
  }

  return {
    fill,
    stroke,
    strokeWidth,
    strokeDash,
    opacity,
    radius: isCollapsed ? TREE_CONFIG.node.radiusCollapsed : radiusBase,
  }
}

/** Constraint type values that have distinct visual treatment (non-default). */
export type ConstraintType = 'DECLARED' | 'NARROWED' | 'PINNED' | 'ADDITIVE' | 'OVERRIDE' | null | undefined

/**
 * Returns a complete set of Tailwind class strings for a small CSS circle indicator
 * matching the given constraint type. Used in the table and legend components.
 *
 * All class strings are complete (not assembled dynamically) so Tailwind's scanner
 * can detect them during the build.
 */
export function constraintCircleClasses(type: ConstraintType): string {
  switch (type) {
    case 'NARROWED':
      return 'bg-yellow-200 border-yellow-700 border-2 border-dashed'
    case 'PINNED':
      return 'bg-orange-100 border-orange-700 border-[3px] border-solid'
    case 'ADDITIVE':
      return 'bg-green-200 border-green-600 border-2 border-dotted'
    case 'OVERRIDE':
      return 'bg-orange-200 border-orange-600 border-[3px] border-dashed'
    default:
      // DECLARED or null/undefined
      return 'bg-blue-200 border-blue-700 border-2 border-solid'
  }
}
