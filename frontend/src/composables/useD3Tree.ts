import { onMounted, onUnmounted, type Ref } from 'vue'
import * as d3 from 'd3'
import type { D3NodeData, TreeNode, SelectedNodeDetail } from '@/types/dependency-tree'
import type { PackageRegistry, VisibleState, VisibleEdge } from '@/types/registry'
import { buildD3DataFromVisibleState, nodeKey } from '@/explorer/transform'
import { PHANTOM_ROOT_KEY } from '@/explorer/visibleState'
import { resolveNodeStyle } from '@/explorer/nodeStyle'
import { renderNodes, applyNodeStyles } from '@/explorer/renderNodes'
import { renderTreeLinks, applyTreeLinkStyles } from '@/explorer/renderTreeLinks'
import { renderSameVersionLinks, applySameVersionLinkStyles } from '@/explorer/renderSameVersionLinks'
import { renderAggregateLinks, applyAggregateLinkStyles } from '@/explorer/renderAggregateLinks'
import { TREE_CONFIG } from '@/explorer/config'
import { useHighlightState } from './useHighlightState'
import { useTreeZoom } from './useTreeZoom'

interface UseD3TreeOptions {
  svgRef: Ref<SVGSVGElement | null>
  onNodeSelect: (node: SelectedNodeDetail | null) => void
  onFoldedNodeExpand?: (registryId: number | null, directName: string | null, packageName: string) => void
  onNavigateBack?: () => void
}

export function useD3Tree(options: UseD3TreeOptions) {
  const { svgRef, onNodeSelect } = options

  // D3 mutable state (not reactive — D3 owns the DOM)
  let root: TreeNode | null = null
  let g: d3.Selection<SVGGElement, unknown, null, undefined> | null = null
  let treeLayout: d3.TreeLayout<D3NodeData> | null = null
  let nameCountMap = new Map<string, number>()
  let aggregateEdges: VisibleEdge[] = []
  let nodesByKey = new Map<string, TreeNode>()
  let currentState: VisibleState | null = null

  const highlight = useHighlightState()
  const zoom = useTreeZoom(svgRef)

  function applyHighlights() {
    if (!g || !root) return
    const state = highlight.getState()

    const relevantTargetKeys = applyAggregateLinkStyles(g, state)

    let effectiveState = state
    if (state.mode === 'focus' && relevantTargetKeys.size > 0) {
      const extTreeLinkKeys = new Set(state.treeLinkTargetKeys)
      const extAncestorKeys = new Set(state.ancestorKeys)

      for (const targetKey of relevantTargetKeys) {
        const targetNode = nodesByKey.get(targetKey)
        if (!targetNode) continue
        extTreeLinkKeys.add(nodeKey(targetNode))
        for (const ancestor of targetNode.ancestors()) {
          const k = nodeKey(ancestor as TreeNode)
          if (ancestor.parent !== null) extTreeLinkKeys.add(k)
          if (!state.primaryKeys.has(k) && !state.secondaryKeys.has(k)) extAncestorKeys.add(k)
        }
      }

      effectiveState = { ...state, treeLinkTargetKeys: extTreeLinkKeys, ancestorKeys: extAncestorKeys }
    }

    applyNodeStyles(g, effectiveState, resolveNodeStyle)
    applyTreeLinkStyles(g, effectiveState)
    applySameVersionLinkStyles(g, effectiveState)
  }

  function update(source: TreeNode) {
    if (!g || !root || !treeLayout) return
    const maxSiblings = Math.max(0, ...root.descendants().map((n) => n.children?.length ?? 0))
    const adaptiveSpacing =
      maxSiblings > TREE_CONFIG.layout.densityThreshold
        ? Math.min(
            TREE_CONFIG.layout.maxNodeSpacing,
            TREE_CONFIG.layout.nodeSize[0] + (maxSiblings - TREE_CONFIG.layout.densityThreshold) * 2,
          )
        : TREE_CONFIG.layout.nodeSize[0]
    treeLayout.nodeSize([adaptiveSpacing, TREE_CONFIG.layout.nodeSize[1]])
    treeLayout(root)

    const nodes = root.descendants() as TreeNode[]
    const links = root.links()

    nameCountMap = new Map()
    nodes.forEach((d) => nameCountMap.set(d.data.name, (nameCountMap.get(d.data.name) ?? 0) + 1))

    renderSameVersionLinks({ g, nodes, onLinkClick: handleNodeSelect })
    renderTreeLinks({ g, links, source, onLinkClick: (node) => handleNodeSelect(node) })
    renderNodes({ g, nodes, source, onNodeClick: handleClick })

    nodesByKey = new Map<string, TreeNode>()
    nodes.forEach((d) => nodesByKey.set(nodeKey(d), d))
    if (currentState?.isNavigated && root) {
      const colW = TREE_CONFIG.layout.nodeSize[1]
      nodesByKey.set(PHANTOM_ROOT_KEY, { x: root.x, y: root.y - colW } as TreeNode)
    }
    renderAggregateLinks({ g, aggregateEdges, nodesByKey, onLinkClick: handleNodeSelect })

    nodes.forEach((d) => {
      d.x0 = d.x
      d.y0 = d.y
    })

    applyHighlights()
    if (currentState?.isNavigated) renderBackEdge(currentState.actualProjectName)
  }

  function handleClick(event: MouseEvent, d: TreeNode) {
    event.stopPropagation()
    if (d.data._hiddenChildCount && d.data?._hiddenChildCount > 0) {
      // Super node: always navigate into that package's subtree.
      if (options.onFoldedNodeExpand && currentState) {
        const vnode = currentState.nodes.get(nodeKey(d))
        if (vnode) {
          options.onFoldedNodeExpand(vnode.registryId, vnode.directName, d.data.name)
        }
      }
      // alt + click for normal nodes to "fold" and "unfold"
    } else if (event.altKey && (d.children || d._children)) {
      // Regular node with D3-loaded children: toggle collapse.
      handleBranchToggle(d)
    } else {
      handleNodeSelect(d)
    }
  }

  function handleNodeSelect(d: TreeNode) {
    if (!root) return
    highlight.focusNode(d, root.descendants() as TreeNode[])
    applyHighlights()
    onNodeSelect({
      name: d.data.name,
      version_installed: d.data.version_installed,
      version_defined: d.data.version_defined,
      latest_version: d.data.latest_version,
      categories: d.data.categories,
      isDuplicate: (nameCountMap.get(d.data.name) ?? 0) > 1,
      time_lag_days: d.data.time_lag_days,
      releases_lag: d.data.releases_lag,
      cve: d.data.cve,
      dependency_path: d.data.dependency_path,
      repo_url: d.data.repo_url,
      homepage_url: d.data.homepage_url,
      package_url: d.data.package_url,
      license: d.data.license,
      purl: d.data.purl,
      constraint_type: d.data.constraint_type,
      constraint_source_file: d.data.constraint_source_file,
      extras: d.data.extras,
      dependencies: d.data.dependencies,
      optional_dependencies: d.data.optional_dependencies,
    })
  }

  function handleBranchToggle(d: TreeNode) {
    if (d.children) {
      d._children = d.children as unknown as TreeNode[]
      ;(d as d3.HierarchyPointNode<D3NodeData>).children = undefined
    } else if (d._children) {
      ;(d as d3.HierarchyPointNode<D3NodeData>).children =
        d._children as unknown as d3.HierarchyPointNode<D3NodeData>[]
      d._children = undefined
    }
    update(d)
  }

  function renderBackEdge(actualProjectName: string) {
    if (!g || !root) return
    g.selectAll('.nav-back-group, .nav-back-edge, .nav-back-edge-hit').remove()

    const colW = TREE_CONFIG.layout.nodeSize[1]
    const rx = root.x
    const phantomY = root.y - colW

    const handleBack = (event: MouseEvent) => {
      event.stopPropagation()
      options.onNavigateBack?.()
    }

    g.insert('line', '.node')
      .attr('class', 'nav-back-edge')
      .attr('x1', phantomY).attr('y1', rx)
      .attr('x2', root.y).attr('y2', rx)
      .attr('stroke', '#94a3b8').attr('stroke-width', 2)
      .attr('stroke-dasharray', '8,4').attr('opacity', 0.6)
      .attr('pointer-events', 'none')

    g.insert('line', '.node')
      .attr('class', 'nav-back-edge-hit')
      .attr('x1', phantomY).attr('y1', rx)
      .attr('x2', root.y).attr('y2', rx)
      .attr('stroke', 'transparent').attr('stroke-width', 14)
      .style('cursor', 'pointer')
      .on('click', handleBack)

    const backGroup = g.insert('g', '.node')
      .attr('class', 'nav-back-group')
      .attr('transform', `translate(${phantomY},${rx})`)
      .style('cursor', 'pointer')
      .on('click', handleBack)

    backGroup.append('circle')
      .attr('r', TREE_CONFIG.node.radiusDefault)
      .attr('fill', TREE_CONFIG.colors.defaultFill)
      .attr('stroke', TREE_CONFIG.colors.defaultStroke)
      .attr('stroke-width', TREE_CONFIG.node.strokeWidth)
      .attr('stroke-dasharray', '4,2')

    backGroup.append('text')
      .attr('class', 'node-label')
      .attr('dy', '-0.6em').attr('x', -12)
      .attr('text-anchor', 'end')
      .text(actualProjectName)
  }

  function handleResize() {
    if (!svgRef.value) return
    const container = svgRef.value.parentElement!
    const width = container.offsetWidth
    const height = container.offsetHeight
    d3.select(svgRef.value).attr('width', width).attr('height', height)
    const effectiveMarginLeft = currentState?.isNavigated
      ? TREE_CONFIG.layout.marginLeft + TREE_CONFIG.layout.nodeSize[1]
      : TREE_CONFIG.layout.marginLeft
    if (g) g.attr('transform', `translate(${effectiveMarginLeft},${height / 2})`)
  }

  function buildTree(registry: PackageRegistry, state: VisibleState, ancestorNames: Set<string>) {
    if (!svgRef.value) return
    highlight.clearFocus()

    const container = svgRef.value.parentElement!
    const width = container.offsetWidth
    const height = container.offsetHeight

    const svg = d3.select(svgRef.value).attr('width', width).attr('height', height)
    svg.selectAll('*').remove()

    const zoomGroup = svg.append('g')
    zoom.initZoom(zoomGroup)

    svg.on('click.outside', () => {
      highlight.clearFocus()
      applyHighlights()
      onNodeSelect(null)
    })

    const effectiveMarginLeft = state.isNavigated
      ? TREE_CONFIG.layout.marginLeft + TREE_CONFIG.layout.nodeSize[1]
      : TREE_CONFIG.layout.marginLeft

    g = zoomGroup
      .append('g')
      .attr('transform', `translate(${effectiveMarginLeft},${height / 2})`)

    treeLayout = d3.tree<D3NodeData>().nodeSize(TREE_CONFIG.layout.nodeSize)
    root = d3.hierarchy(buildD3DataFromVisibleState(registry, state, ancestorNames)) as unknown as TreeNode
    root.x0 = 0
    root.y0 = 0
    aggregateEdges = state.edges.filter((e) => e.isAggregate)
    currentState = state

    update(root)
  }

  function initializeTree(
    registry: PackageRegistry,
    state: VisibleState,
    ancestorNames: Set<string> = new Set(),
  ) {
    if (!svgRef.value) return
    const doRebuild = () => buildTree(registry, state, ancestorNames)
    if (g) {
      // Fade out the current tree, then rebuild. interrupt() cancels any pending transition
      // without firing its 'end' callback, so rapid calls don't queue multiple rebuilds.
      g.interrupt()
        .style('pointer-events', 'none')
        .transition()
        .duration(TREE_CONFIG.animation.fadeDuration)
        .style('opacity', '0')
        .on('end', () => doRebuild())
    } else {
      doRebuild()
    }
  }

  onMounted(() => window.addEventListener('resize', handleResize))
  onUnmounted(() => window.removeEventListener('resize', handleResize))

  function selectNodeByName(name: string) {
    if (!root) return
    const target = (root.descendants() as TreeNode[]).find((d) => d.data.name === name)
    if (target) handleNodeSelect(target)
  }

  return { initializeTree, selectNodeByName, zoomIn: zoom.zoomIn, zoomOut: zoom.zoomOut, resetZoom: zoom.resetZoom }
}
