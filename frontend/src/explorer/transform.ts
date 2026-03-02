import type * as d3 from 'd3'
import type { DependencyNode, D3NodeData } from '@/types/dependency-tree'

/**
 * Unique key for a tree node based on its ancestor path (e.g. "root/react/lodash").
 * Path-based keys are necessary because duplicate package names appear in multiple subtrees.
 */
export function nodeKey(d: d3.HierarchyNode<D3NodeData>): string {
  return d
    .ancestors()
    .map((a) => a.data.name)
    .reverse()
    .join('/')
}

/**
 * Converts the backend DependencyNode format into the D3-compatible D3NodeData format.
 * Cycle-safe: skips any node whose name is already in the current ancestor chain.
 */
export function transformToD3(
  node: DependencyNode,
  ancestors: Set<string> = new Set(),
): D3NodeData {
  const children: D3NodeData[] = []
  if (node.dependencies) {
    Object.entries(node.dependencies).forEach(([, dep]) => {
      if (!ancestors.has(dep.name)) {
        const childAncestors = new Set(ancestors)
        childAncestors.add(dep.name)
        children.push(transformToD3(dep, childAncestors))
      }
      // else: true cycle — skip silently
    })
  }
  return { ...node, children: children.length > 0 ? children : null }
}
