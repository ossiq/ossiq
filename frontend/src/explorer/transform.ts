import type * as d3 from 'd3'
import type { DependencyNode, D3NodeData } from '@/types/dependency-tree'
import type { PackageRegistry, VisibleState } from '@/types/registry'

/**
 * Unique key for a tree node based on its ancestor path (e.g. "root/react/lodash").
 * Path-based keys are necessary because duplicate package names appear in multiple subtrees.
 */
export function nodeKey(d: d3.HierarchyNode<D3NodeData>): string {
  if (d.data._key !== undefined) return d.data._key
  return d.ancestors().map((a) => a.data.name).reverse().join('>')
}

/**
 * Builds a D3NodeData tree from a VisibleState slice, looking up package metrics from the
 * registry. Only nodes present in state.nodes are included; children are derived from edges.
 *
 * ancestorNames: package names from the nav stack. Non-root nodes whose name matches get
 * _isAncestorRef = true, which renders a "↩" badge to signal DAG loop-back to a parent view.
 */
export function buildD3DataFromVisibleState(
  registry: PackageRegistry,
  state: VisibleState,
  ancestorNames: Set<string> = new Set(),
): D3NodeData {
  // Group edges by sourceKey for O(1) children lookup
  const childEdgeMap = new Map<string, typeof state.edges>()
  for (const edge of state.edges) {
    let list = childEdgeMap.get(edge.sourceKey)
    if (!list) {
      list = []
      childEdgeMap.set(edge.sourceKey, list)
    }
    list.push(edge)
  }

  function buildNode(key: string, versionDefinedOverride?: string): D3NodeData {
    const vnode = state.nodes.get(key)
    if (!vnode) {
      // Fallback for missing nodes (shouldn't happen in practice)
      return { name: key, version_installed: '', children: null, _key: key }
    }

    const childEdges = childEdgeMap.get(key) ?? []
    const children: D3NodeData[] = childEdges
      .filter((edge) => !edge.isAggregate)
      .map((edge) => buildNode(edge.targetKey, edge.edgeData.version_constraint))

    // Root node — never gets _isAncestorRef
    if (key === state.rootKey) {
      return {
        name: state.projectName,
        version_installed: 'local',
        categories: [],
        children: children.length ? children : null,
        _key: key,
        _isFolded: vnode.isFolded,
        _hiddenChildCount: vnode.hiddenChildCount,
      }
    }

    // Direct (production) package node
    if (vnode.directName !== null) {
      const de = registry.directEntries.get(vnode.directName)
      const packageName = de?.package_name ?? vnode.directName
      return {
        name: packageName,
        version_installed: de?.installed_version ?? '',
        version_defined: versionDefinedOverride ?? de?.version_constraint ?? undefined,
        latest_version: de?.latest_version ?? undefined,
        severity: de?.severity ?? undefined,
        time_lag_days: de?.time_lag_days ?? undefined,
        releases_lag: de?.releases_lag ?? undefined,
        cve: de?.cve ?? [],
        constraint_type: de?.constraint_type ?? null,
        constraint_source_file: de?.constraint_source_file ?? null,
        categories: ['production'],
        children: children.length ? children : null,
        _key: key,
        _isFolded: vnode.isFolded,
        _hiddenChildCount: vnode.hiddenChildCount,
        _isAncestorRef: ancestorNames.size > 0 && ancestorNames.has(packageName),
      }
    }

    // Transitive package node
    const re = vnode.registryId !== null ? registry.byId.get(vnode.registryId) : undefined
    const packageName = re?.package_name ?? key.split('>').at(-1) ?? key
    return {
      name: packageName,
      version_installed: re?.installed_version ?? '',
      version_defined: versionDefinedOverride,
      latest_version: re?.latest_version ?? undefined,
      severity: re?.severity ?? undefined,
      time_lag_days: re?.time_lag_days ?? undefined,
      releases_lag: re?.releases_lag ?? undefined,
      cve: re?.cve ?? [],
      constraint_source_file: re?.constraint_source_file ?? null,
      repo_url: re?.repo_url ?? null,
      homepage_url: re?.homepage_url ?? null,
      package_url: re?.package_url ?? null,
      license: re?.license ?? null,
      purl: re?.purl ?? null,
      categories: ['transitive'],
      children: children.length ? children : null,
      _key: key,
      _isFolded: vnode.isFolded,
      _hiddenChildCount: vnode.hiddenChildCount,
      _isAncestorRef: ancestorNames.size > 0 && ancestorNames.has(packageName),
    }
  }

  return buildNode(state.rootKey)
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
