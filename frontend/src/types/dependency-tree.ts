import type { HierarchyPointNode } from 'd3'

export interface DependencyNode {
  name: string
  version_installed: string
  version_defined?: string
  source?: string | null
  required_engine?: string | null
  latest_version?: string
  severity?: string
  categories?: string[]
  dependencies?: Record<string, DependencyNode>
  optional_dependencies?: Record<string, DependencyNode>
}

export interface D3NodeData extends DependencyNode {
  children: D3NodeData[] | null
}

export interface SelectedNodeDetail {
  name: string
  version_installed: string
  version_defined?: string
  latest_version?: string
  categories?: string[]
  isDuplicate: boolean
}

export interface TreeNode extends HierarchyPointNode<D3NodeData> {
  _children?: TreeNode[] | null
  x0?: number
  y0?: number
}

/** Resolved visual style for a single node, computed from node state + highlight state. */
export interface NodeStyle {
  fill: string
  stroke: string
  strokeWidth: number
  opacity: number
  radius: number
}

/** Snapshot of which nodes/links are currently highlighted. Passed into all render functions. */
export interface HighlightState {
  mode: 'none' | 'focus'
  primaryKeys: ReadonlySet<string>        // clicked node (blue)
  secondaryKeys: ReadonlySet<string>      // same-version duplicates (amber)
  ancestorKeys: ReadonlySet<string>       // ancestors of primary/secondary (full opacity)
  treeLinkTargetKeys: ReadonlySet<string> // tree edge target keys along ancestor paths
  dashedLinkPairs: ReadonlySet<string>    // same-version dashed link pair keys to highlight
  hasCveInPath: boolean                   // true if any highlighted ancestor node has a CVE
}
