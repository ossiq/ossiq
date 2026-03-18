import { nodeKey } from '@/explorer/transform'
import type { TreeNode, HighlightState } from '@/types/dependency-tree'

/**
 * Manages the highlight/focus state for the dependency tree explorer.
 * All five highlight Sets live here — nothing else in the codebase mutates them.
 *
 * Usage:
 *   const highlight = useHighlightState()
 *   highlight.focusNode(clickedNode, allNodes)  // set focus on a node
 *   highlight.clearFocus()                       // reset to no-highlight
 *   renderNodes({ ..., highlight: highlight.getState() })
 */
export function useHighlightState() {
  let mode: 'none' | 'focus' = 'none'
  let primaryKeys = new Set<string>()             // clicked node (blue)
  let secondaryKeys = new Set<string>()           // same-version duplicates (amber)
  let ancestorKeys = new Set<string>()            // ancestor path nodes (full opacity)
  let treeLinkTargetKeys = new Set<string>()      // tree edge targets along ancestor paths
  let dashedLinkPairs = new Set<string>()         // same-version dashed link pair keys
  let descendantKeys = new Set<string>()          // all descendants of primary+secondary
  let descendantLinkTargetKeys = new Set<string>() // tree edge targets going DOWN from focused nodes

  function clearFocus() {
    mode = 'none'
    primaryKeys = new Set()
    secondaryKeys = new Set()
    ancestorKeys = new Set()
    treeLinkTargetKeys = new Set()
    dashedLinkPairs = new Set()
    descendantKeys = new Set()
    descendantLinkTargetKeys = new Set()
  }

  function collectDescendantInfo(nodes: TreeNode[]) {
    descendantKeys = new Set()
    descendantLinkTargetKeys = new Set()
    for (const node of nodes) {
      node.descendants().slice(1).forEach((desc) => {
        const k = nodeKey(desc as TreeNode)
        descendantLinkTargetKeys.add(k)
        if (!primaryKeys.has(k) && !secondaryKeys.has(k)) {
          descendantKeys.add(k)
        }
      })
    }
  }

  function collectAncestorInfo(nodes: TreeNode[]) {
    ancestorKeys = new Set()
    treeLinkTargetKeys = new Set()
    for (const node of nodes) {
      treeLinkTargetKeys.add(nodeKey(node))
      node.ancestors().forEach((ancestor) => {
        const k = nodeKey(ancestor as TreeNode)
        if (ancestor.parent !== null) {
          treeLinkTargetKeys.add(k)
        }
        if (!primaryKeys.has(k) && !secondaryKeys.has(k)) {
          ancestorKeys.add(k)
        }
      })
    }
  }

  function getDashedPairsForVersion(versionKey: string, allNodes: TreeNode[]): Set<string> {
    const group = allNodes.filter(
      (n) => `${n.data.name}@${n.data.version_installed}` === versionKey,
    )
    const pairs = new Set<string>()
    for (let i = 0; i < group.length - 1; i++) {
      pairs.add(`${nodeKey(group[i]!)}--${nodeKey(group[i + 1]!)}`)
    }
    return pairs
  }

  /** Focus on a node and its same-version duplicates, highlighting the ancestor path to root. */
  function focusNode(node: TreeNode, allNodes: TreeNode[]) {
    const dKey = nodeKey(node)
    const versionKey = `${node.data.name}@${node.data.version_installed}`
    const duplicates = allNodes.filter(
      (n) => `${n.data.name}@${n.data.version_installed}` === versionKey && nodeKey(n) !== dKey,
    )

    mode = 'focus'
    primaryKeys = new Set([dKey])
    secondaryKeys = new Set(duplicates.map((n) => nodeKey(n)))
    collectAncestorInfo([node, ...duplicates])
    collectDescendantInfo([node, ...duplicates])
    dashedLinkPairs = getDashedPairsForVersion(versionKey, allNodes)
  }

  /** Returns an immutable snapshot of the current highlight state for passing to render functions. */
  function getState(): HighlightState {
    return { mode, primaryKeys, secondaryKeys, ancestorKeys, treeLinkTargetKeys, dashedLinkPairs, descendantKeys, descendantLinkTargetKeys }
  }

  return { focusNode, clearFocus, getState }
}
