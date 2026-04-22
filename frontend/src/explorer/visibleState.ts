import type { PackageRegistry, VisibleState, VisibleNode, VisibleEdge, EdgeData } from '@/types/registry'

interface QueueEntry {
  key: string
  depth: number
  registryId: number | null
  directName: string | null
  ancestorNames: ReadonlySet<string>
}

export function buildVisibleState(
  registry: PackageRegistry,
  projectName: string,
  rootKey: string = 'root',
  maxDepth: number = 2,
): VisibleState {
  const nodes = new Map<string, VisibleNode>()
  const edges: VisibleEdge[] = []

  nodes.set(rootKey, {
    key: rootKey,
    registryId: null,
    directName: null,
    depth: 0,
    isFolded: false,
    hiddenChildCount: 0,
  })

  const queue: QueueEntry[] = []
  const rootAncestors = new Set<string>([rootKey])

  for (const [name, directEntry] of registry.directEntries) {
    const childKey = `${rootKey}/${name}`
    const edgeData: EdgeData = { ct: directEntry.constraint_type ?? 'DECLARED' }
    if (directEntry.version_constraint) edgeData.version_constraint = directEntry.version_constraint
    edges.push({ sourceKey: rootKey, targetKey: childKey, edgeData, isAggregate: false })
    queue.push({ key: childKey, depth: 1, registryId: null, directName: name, ancestorNames: rootAncestors })
  }

  while (queue.length > 0) {
    const entry = queue.shift()!
    const { key, depth, registryId, directName, ancestorNames } = entry

    if (nodes.has(key)) continue

    // Collect child refs for this node
    const childRefs: Array<{ ref: number; edgeData: EdgeData }> = []
    if (directName !== null) {
      const de = registry.directEntries.get(directName)
      if (de) childRefs.push(...de.childRefs)
    } else if (registryId !== null) {
      const re = registry.byId.get(registryId)
      if (re) {
        for (const [ref, edgeData] of re.childEdges) {
          childRefs.push({ ref, edgeData })
        }
      }
    }

    const isFolded = depth >= maxDepth && childRefs.length > 0
    nodes.set(key, {
      key,
      registryId,
      directName,
      depth,
      isFolded,
      hiddenChildCount: isFolded ? childRefs.length : 0,
    })

    if (depth < maxDepth) {
      const childAncestors = new Set(ancestorNames)
      childAncestors.add(key)

      for (const { ref, edgeData } of childRefs) {
        const child = registry.byId.get(ref)
        if (!child) continue
        // Skip true cycles: package name already in ancestor chain
        if (ancestorNames.has(child.package_name)) continue
        const childKey = `${key}/${child.package_name}`
        edges.push({ sourceKey: key, targetKey: childKey, edgeData, isAggregate: false })
        queue.push({ key: childKey, depth: depth + 1, registryId: ref, directName: null, ancestorNames: childAncestors })
      }
    }
  }

  return { nodes, edges, rootKey, maxDepth, projectName }
}
