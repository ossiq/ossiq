import Fuse from 'fuse.js'
import { ref, watch, computed, onUnmounted, type Ref } from 'vue'
import type { DependencyNode } from '@/types/dependency-tree'
import { isPinned, hasUpperConstraint } from '@/explorer/nodeStyle'

/**
 * A named toggle filter with its predicate.
 * To add a new filter type: add an entry to TOGGLE_FILTERS below.
 * No other code needs to change.
 */
export interface ToggleFilter {
  key: string
  test: (node: DependencyNode) => boolean
}

const TOGGLE_FILTERS: ToggleFilter[] = [
  { key: 'cve', test: (n) => !!n.severity },
  { key: 'pinned', test: (n) => isPinned(n.version_defined) },
  { key: 'upperBound', test: (n) => hasUpperConstraint(n.version_defined) },
]

/** Recursively collects all DependencyNode instances (excluding the root) into a flat list. */
function collectAllNodes(node: DependencyNode, result: DependencyNode[] = []): DependencyNode[] {
  for (const child of Object.values(node.dependencies ?? {})) {
    result.push(child)
    collectAllNodes(child, result)
  }
  for (const child of Object.values(node.optional_dependencies ?? {})) {
    result.push(child)
    collectAllNodes(child, result)
  }
  return result
}

/**
 * Returns a pruned copy of node, or null if the branch has no matches.
 * - Root is always returned (children still pruned).
 * - A non-root node is kept if it directly satisfies the predicate OR if any descendant does.
 */
function pruneTree(
  node: DependencyNode,
  predicate: (n: DependencyNode) => boolean,
  isRoot = false,
): DependencyNode | null {
  let prunedDeps: Record<string, DependencyNode> | undefined
  if (node.dependencies) {
    const kept: [string, DependencyNode][] = []
    for (const [key, child] of Object.entries(node.dependencies)) {
      const pruned = pruneTree(child, predicate)
      if (pruned !== null) kept.push([key, pruned])
    }
    if (kept.length > 0) prunedDeps = Object.fromEntries(kept)
  }

  let prunedOptional: Record<string, DependencyNode> | undefined
  if (node.optional_dependencies) {
    const kept: [string, DependencyNode][] = []
    for (const [key, child] of Object.entries(node.optional_dependencies)) {
      const pruned = pruneTree(child, predicate)
      if (pruned !== null) kept.push([key, pruned])
    }
    if (kept.length > 0) prunedOptional = Object.fromEntries(kept)
  }

  const hasMatchingDescendant = !!prunedDeps || !!prunedOptional

  if (isRoot || predicate(node) || hasMatchingDescendant) {
    return { ...node, dependencies: prunedDeps, optional_dependencies: prunedOptional }
  }

  return null
}

/**
 * Builds the combined predicate from active search results and toggle states.
 *
 * Logic:
 * - No filters → returns null (signals full passthrough, skips pruning)
 * - Only toggles → OR between active toggles
 * - Only search → name must be in matched set
 * - Both → AND (name must match search AND satisfy at least one active toggle)
 */
function buildPredicate(
  matchedNames: Set<string> | null,
  activeToggleTests: Array<(n: DependencyNode) => boolean>,
): ((n: DependencyNode) => boolean) | null {
  if (matchedNames === null && activeToggleTests.length === 0) return null

  return (node: DependencyNode) => {
    const searchOk = matchedNames === null || matchedNames.has(node.name)
    const toggleOk = activeToggleTests.length === 0 || activeToggleTests.some((test) => test(node))
    return searchOk && toggleOk
  }
}

export interface UseTreeFiltersOptions {
  dependencyTree: Ref<DependencyNode | null>
}

export function useTreeFilters({ dependencyTree }: UseTreeFiltersOptions) {
  const searchQuery = ref('')
  const filterCve = ref(false)
  const filterPinned = ref(false)
  const filterUpperBound = ref(false)

  // Fuse.js index, rebuilt when the tree changes
  let fuseIndex: Fuse<DependencyNode> | null = null

  watch(
    dependencyTree,
    (tree) => {
      if (!tree) {
        fuseIndex = null
        return
      }
      fuseIndex = new Fuse(collectAllNodes(tree), {
        keys: ['name'],
        threshold: 0.35,
        minMatchCharLength: 2,
        shouldSort: false,
      })
    },
    { immediate: true },
  )

  // 50ms debounced search query — filteredTree reads this, not searchQuery directly
  const debouncedQuery = ref('')
  let debounceTimer: ReturnType<typeof setTimeout> | null = null

  watch(searchQuery, (q) => {
    if (debounceTimer) clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => {
      debouncedQuery.value = q
    }, 50)
  })

  onUnmounted(() => {
    if (debounceTimer) clearTimeout(debounceTimer)
  })

  const toggleMap: Record<string, Ref<boolean>> = {
    cve: filterCve,
    pinned: filterPinned,
    upperBound: filterUpperBound,
  }

  const hasActiveFilters = computed(
    () => !!searchQuery.value || filterCve.value || filterPinned.value || filterUpperBound.value,
  )

  function clearFilters() {
    searchQuery.value = ''
    filterCve.value = false
    filterPinned.value = false
    filterUpperBound.value = false
  }

  const filteredTree = computed<DependencyNode | null>(() => {
    const tree = dependencyTree.value
    if (!tree) return null

    // Resolve fuzzy-matched name set
    let matchedNames: Set<string> | null = null
    const q = debouncedQuery.value.trim()
    if (q && fuseIndex) {
      matchedNames = new Set(fuseIndex.search(q).map((r) => r.item.name))
    }

    // Resolve active toggle predicates (OR between active ones)
    const activeToggleTests = TOGGLE_FILTERS.filter((f) => toggleMap[f.key]?.value === true).map(
      (f) => f.test,
    )

    const predicate = buildPredicate(matchedNames, activeToggleTests)
    if (predicate === null) return tree

    return pruneTree(tree, predicate, true)
  })

  return { searchQuery, filterCve, filterPinned, filterUpperBound, filteredTree, hasActiveFilters, clearFilters }
}
