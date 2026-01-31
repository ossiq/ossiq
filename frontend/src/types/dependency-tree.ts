import type { HierarchyPointNode } from 'd3'

export interface DependencyNode {
  name: string
  version_installed: string
  version_defined?: string
  latest_version?: string
  categories?: string[]
  dependencies?: Record<string, DependencyNode>
}

export interface D3NodeData extends DependencyNode {
  children: D3NodeData[] | null
}

export interface CrossLink {
  parentName: string
  targetName: string
  targetData: DependencyNode
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
  _clickCycle: number
  _children?: TreeNode[] | null
  x0?: number
  y0?: number
}
