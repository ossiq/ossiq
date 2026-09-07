import type * as d3 from 'd3'
import type { DependencyNode, D3NodeData } from '@/types/dependency-tree'
import type { PackageRegistry, VisibleState } from '@/types/registry'

function hasCveInSubtree(startRefs: number[], registry: PackageRegistry): boolean {
  const visited = new Set<number>()
  const queue = [...startRefs]
  while (queue.length > 0) {
    const ref = queue.pop()!
    if (visited.has(ref)) continue
    visited.add(ref)
    const re = registry.byId.get(ref)
    if (!re) continue
    if (re.severity != null) return true
    for (const [childRef] of re.childEdges) {
      if (!visited.has(childRef)) queue.push(childRef)
    }
  }
  return false
}

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

    // Compute CVE presence for folded nodes by BFS-ing the hidden subtree in the registry
    let _hasChildCve = false
    if (vnode.isFolded) {
      const childRefs: number[] = []
      if (vnode.directName !== null) {
        const de = registry.directEntries.get(vnode.directName)
        if (de) childRefs.push(...de.childRefs.map(({ ref }) => ref))
      } else if (vnode.registryId !== null) {
        const re = registry.byId.get(vnode.registryId)
        if (re) for (const [ref] of re.childEdges) childRefs.push(ref)
      }
      _hasChildCve = hasCveInSubtree(childRefs, registry)
    }

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
        _hasChildCve,
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
        version_age_days: de?.version_age_days ?? undefined,
        releases_lag: de?.releases_lag ?? undefined,
        cve: de?.cve ?? [],
        constraint_type: de?.constraint_type ?? null,
        constraint_source_file: de?.constraint_source_file ?? null,
        repo_url: de?.repo_url ?? null,
        homepage_url: de?.homepage_url ?? null,
        package_url: de?.package_url ?? null,
        license: de?.license ?? null,
        purl: de?.purl ?? null,
        extras: de?.extras ?? null,
        is_yanked: de?.is_yanked,
        is_prerelease: de?.is_prerelease,
        is_deprecated: de?.is_deprecated,
        is_package_unpublished: de?.is_package_unpublished,
        epss: de?.epss ?? null,
        maintenance_coverage: de?.maintenance_coverage ?? null,
        maintenance_risk: de?.maintenance_risk ?? null,
        maintenance_state: de?.maintenance_state ?? null,
        flow_trend: de?.flow_trend ?? null,
        deprecation_signals: de?.deprecation_signals ?? [],
        deprecation_successor: de?.deprecation_successor ?? null,
        gap_cv: de?.gap_cv ?? null,
        silence_days: de?.silence_days ?? null,
        silence_p: de?.silence_p ?? null,
        commits_sampled: de?.commits_sampled ?? null,
        archived: de?.archived ?? null,
        days_since_push: de?.days_since_push ?? null,
        triage_action: de?.triage_action ?? null,
        categories: ['production'],
        children: children.length ? children : null,
        _key: key,
        _isFolded: vnode.isFolded,
        _hiddenChildCount: vnode.hiddenChildCount,
        _hasChildCve,
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
      version_age_days: re?.version_age_days ?? undefined,
      releases_lag: re?.releases_lag ?? undefined,
      cve: re?.cve ?? [],
      constraint_source_file: re?.constraint_source_file ?? null,
      is_yanked: re?.is_yanked,
      is_prerelease: re?.is_prerelease,
      is_deprecated: re?.is_deprecated,
      is_package_unpublished: re?.is_package_unpublished,
      epss: re?.epss ?? null,
      maintenance_coverage: re?.maintenance_coverage ?? null,
      maintenance_risk: re?.maintenance_risk ?? null,
      maintenance_state: re?.maintenance_state ?? null,
      flow_trend: re?.flow_trend ?? null,
      deprecation_signals: re?.deprecation_signals ?? [],
      deprecation_successor: re?.deprecation_successor ?? null,
      gap_cv: re?.gap_cv ?? null,
      silence_days: re?.silence_days ?? null,
      silence_p: re?.silence_p ?? null,
      commits_sampled: re?.commits_sampled ?? null,
      archived: re?.archived ?? null,
      days_since_push: re?.days_since_push ?? null,
      triage_action: re?.triage_action ?? null,
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
      _hasChildCve,
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
