import type { PackageRegistry, VisibleState, VisibleNode, VisibleEdge, EdgeData, NavFrame } from '@/types/registry'

interface QueueEntry {
  key: string
  depth: number
  registryId: number | null
  directName: string | null
  /** Package names of strict ancestors — used for true-cycle detection (not path keys). */
  ancestorPackageNames: ReadonlySet<string>
  /** Effective max depth for this subtree; may be raised when an ancestor is in expandedKeys. */
  localMax: number
}

/**
 * BFS from the project root (or a navigated sub-tree root) up to maxDepth levels.
 *
 * - Nodes at depth === localMax that still have children are marked isFolded.
 * - filterMask: when non-null, only includes nodes whose package_name is in the set.
 *   Build from filteredTree (useTreeFilters) to keep both matched nodes and their ancestors.
 * - expandedKeys: kept for API compatibility; callers pass new Set() in Phase 3+.
 * - navRoot: when provided, BFS seeds from that package's children instead of
 *   registry.directEntries. Used for shift-and-expand navigation.
 * - After BFS, a second pass finds hidden children of folded nodes that are already visible
 *   elsewhere in the tree and adds isAggregate edges for them.
 */
export function buildVisibleState(
  registry: PackageRegistry,
  projectName: string,
  rootKey: string = 'root',
  maxDepth: number = 2,
  filterMask: Set<string> | null = null,
  expandedKeys: ReadonlySet<string> = new Set(),
  navRoot: NavFrame | null = null,
): VisibleState {
  const nodes = new Map<string, VisibleNode>()
  const edges: VisibleEdge[] = []
  // First visible key per registryId — used for aggregate detection
  const registryIdToKey = new Map<number, string>()

  nodes.set(rootKey, {
    key: rootKey,
    registryId: navRoot?.registryId ?? null,
    directName: navRoot?.directName ?? null,
    depth: 0,
    isFolded: false,
    hiddenChildCount: 0,
  })

  const queue: QueueEntry[] = []
  // Root ancestor set prevents the root package from re-appearing as its own descendant
  const rootLabel = navRoot ? navRoot.label : projectName
  const rootAncestorNames = new Set<string>([rootLabel])

  if (navRoot === null) {
    // Default: seed from all direct production dependencies
    for (const [name, directEntry] of registry.directEntries) {
      if (filterMask !== null && !filterMask.has(name)) continue
      const childKey = `${rootKey}>${name}`
      const edgeData: EdgeData = { ct: directEntry.constraint_type ?? 'DECLARED' }
      if (directEntry.version_constraint) edgeData.version_constraint = directEntry.version_constraint
      edges.push({ sourceKey: rootKey, targetKey: childKey, edgeData, isAggregate: false })
      queue.push({
        key: childKey,
        depth: 1,
        registryId: null,
        directName: name,
        ancestorPackageNames: rootAncestorNames,
        localMax: maxDepth,
      })
    }
  } else {
    // Navigated: seed from the clicked package's children
    const childRefSeed: Array<{ ref: number; edgeData: EdgeData }> = []
    if (navRoot.directName !== null) {
      const de = registry.directEntries.get(navRoot.directName)
      if (de) childRefSeed.push(...de.childRefs)
    } else if (navRoot.registryId !== null) {
      const re = registry.byId.get(navRoot.registryId)
      if (re) for (const [ref, edgeData] of re.childEdges) childRefSeed.push({ ref, edgeData })
    }
    for (const { ref, edgeData } of childRefSeed) {
      const child = registry.byId.get(ref)
      if (!child) continue
      if (filterMask !== null && !filterMask.has(child.package_name)) continue
      const childKey = `${rootKey}>${child.package_name}`
      edges.push({ sourceKey: rootKey, targetKey: childKey, edgeData, isAggregate: false })
      queue.push({
        key: childKey,
        depth: 1,
        registryId: ref,
        directName: null,
        ancestorPackageNames: rootAncestorNames,
        localMax: maxDepth,
      })
    }
  }

  while (queue.length > 0) {
    const entry = queue.shift()!
    const { key, depth, registryId, directName, ancestorPackageNames, localMax } = entry

    if (nodes.has(key)) continue

    // Raise effective max if this node was explicitly expanded
    const myMax = expandedKeys.has(key) ? Math.max(localMax, depth + 3) : localMax

    // Collect children of this node
    const childRefs: Array<{ ref: number; edgeData: EdgeData }> = []
    if (directName !== null) {
      const de = registry.directEntries.get(directName)
      if (de) childRefs.push(...de.childRefs)
    } else if (registryId !== null) {
      const re = registry.byId.get(registryId)
      if (re) {
        for (const [ref, edgeData] of re.childEdges) childRefs.push({ ref, edgeData })
      }
    }

    const isFolded = depth >= myMax && childRefs.length > 0
    nodes.set(key, {
      key,
      registryId,
      directName,
      depth,
      isFolded,
      hiddenChildCount: isFolded ? childRefs.length : 0,
    })

    if (registryId !== null && !registryIdToKey.has(registryId)) {
      registryIdToKey.set(registryId, key)
    }

    if (depth < myMax) {
      const currentName = directName ?? registry.byId.get(registryId!)?.package_name
      const childAncestorNames = new Set(ancestorPackageNames)
      if (currentName) childAncestorNames.add(currentName)

      for (const { ref, edgeData } of childRefs) {
        const child = registry.byId.get(ref)
        if (!child) continue
        if (ancestorPackageNames.has(child.package_name)) continue // true cycle
        if (filterMask !== null && !filterMask.has(child.package_name)) continue
        const childKey = `${key}>${child.package_name}`
        edges.push({ sourceKey: key, targetKey: childKey, edgeData, isAggregate: false })
        queue.push({
          key: childKey,
          depth: depth + 1,
          registryId: ref,
          directName: null,
          ancestorPackageNames: childAncestorNames,
          localMax: myMax,
        })
      }
    }
  }

  // Aggregate detection: for each folded node, check whether any of its hidden children
  // are already visible elsewhere. If so, draw a single aggregate link instead of counting
  // them as hidden, which reduces the fold count and adds visual cross-tree context.
  for (const [, node] of nodes) {
    if (!node.isFolded) continue

    const hiddenChildRefs: Array<{ ref: number; edgeData: EdgeData }> = []
    if (node.directName !== null) {
      const de = registry.directEntries.get(node.directName)
      if (de) hiddenChildRefs.push(...de.childRefs)
    } else if (node.registryId !== null) {
      const re = registry.byId.get(node.registryId)
      if (re) {
        for (const [ref, edgeData] of re.childEdges) hiddenChildRefs.push({ ref, edgeData })
      }
    }

    const seen = new Set<number>()
    let aggregated = 0
    for (const { ref, edgeData } of hiddenChildRefs) {
      if (seen.has(ref)) continue
      seen.add(ref)
      const targetKey = registryIdToKey.get(ref)
      if (targetKey && targetKey !== node.key) {
        // source = visible dep, target = super node (arc points TO the super node circle)
        edges.push({ sourceKey: targetKey, targetKey: node.key, edgeData, isAggregate: true })
        aggregated++
      }
    }
    if (aggregated > 0) {
      node.hiddenChildCount = Math.max(0, node.hiddenChildCount - aggregated)
      if (node.hiddenChildCount === 0) {
        node.isFolded = false // all hidden children are visible elsewhere via aggregate links
      }
    }
  }

  // Bug 3: in navigated views, any package that appears in 2+ branches (reused transitive dep)
  // gets an aggregate back-edge to the view root — a visual signal of cross-cutting reuse.
  if (navRoot !== null) {
    const registryIdToNodeKeys = new Map<number, string[]>()
    for (const [key, node] of nodes) {
      if (key === rootKey || node.registryId === null) continue
      const arr = registryIdToNodeKeys.get(node.registryId) ?? []
      arr.push(key)
      registryIdToNodeKeys.set(node.registryId, arr)
    }
    const addedToRoot = new Set<string>()
    for (const [, keys] of registryIdToNodeKeys) {
      if (keys.length < 2) continue
      for (const key of keys) {
        if (addedToRoot.has(key)) continue
        addedToRoot.add(key)
        edges.push({ sourceKey: key, targetKey: rootKey, edgeData: { ct: 'DECLARED' }, isAggregate: true })
      }
    }
  }

  return { nodes, edges, rootKey, maxDepth, projectName: rootLabel, isNavigated: navRoot !== null, actualProjectName: projectName }
}
