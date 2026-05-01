import type { HierarchyPointNode } from 'd3'
import type { CVEInfo } from '@/types/report'

export interface DependencyNode {
  name: string
  version_installed: string
  version_defined?: string
  source?: string | null
  required_engine?: string | null
  latest_version?: string
  severity?: string
  categories?: string[]
  time_lag_days?: number | null
  releases_lag?: number | null
  cve?: CVEInfo[]
  dependency_path?: string[] | null
  repo_url?: string | null
  homepage_url?: string | null
  package_url?: string | null
  license?: string[] | null
  purl?: string | null
  constraint_type?: 'DECLARED' | 'NARROWED' | 'PINNED' | 'ADDITIVE' | 'OVERRIDE' | null
  constraint_source_file?: string | null
  extras?: string[] | null
  is_prerelease?: boolean
  is_yanked?: boolean
  is_deprecated?: boolean
  is_package_unpublished?: boolean
  dependencies?: Record<string, DependencyNode>
  optional_dependencies?: Record<string, DependencyNode>
}

export interface D3NodeData extends DependencyNode {
  children: D3NodeData[] | null
  _key?: string
  _isFolded?: boolean
  _hiddenChildCount?: number
  _hasChildCve?: boolean
  _isAncestorRef?: boolean
}

export interface SelectedNodeDetail {
  name: string
  version_installed: string
  version_defined?: string
  latest_version?: string
  categories?: string[]
  isDuplicate: boolean
  time_lag_days?: number | null
  releases_lag?: number | null
  cve?: CVEInfo[]
  dependency_path?: string[] | null
  repo_url?: string | null
  homepage_url?: string | null
  package_url?: string | null
  license?: string[] | null
  purl?: string | null
  constraint_type?: 'DECLARED' | 'NARROWED' | 'PINNED' | 'ADDITIVE' | 'OVERRIDE' | null
  constraint_source_file?: string | null
  extras?: string[] | null
  is_prerelease?: boolean
  is_yanked?: boolean
  is_deprecated?: boolean
  is_package_unpublished?: boolean
  dependencies?: Record<string, DependencyNode>
  optional_dependencies?: Record<string, DependencyNode>
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
  strokeDash: string
  opacity: number
  radius: number
}

/** Snapshot of which nodes/links are currently highlighted. Passed into all render functions. */
export interface HighlightState {
  mode: 'none' | 'focus'
  primaryKeys: ReadonlySet<string>             // clicked node (blue)
  secondaryKeys: ReadonlySet<string>           // same-version duplicates (amber)
  ancestorKeys: ReadonlySet<string>            // ancestors of primary/secondary (full opacity)
  treeLinkTargetKeys: ReadonlySet<string>      // tree edge target keys along ancestor paths
  dashedLinkPairs: ReadonlySet<string>         // same-version dashed link pair keys to highlight
  descendantKeys: ReadonlySet<string>          // all descendants of primary+secondary (full opacity)
  descendantLinkTargetKeys: ReadonlySet<string> // tree edge targets going DOWN from focused nodes
}
