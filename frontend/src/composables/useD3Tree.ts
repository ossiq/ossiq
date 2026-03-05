import { onMounted, onUnmounted, type Ref } from 'vue'
import * as d3 from 'd3'
import type { DependencyNode, D3NodeData, TreeNode, SelectedNodeDetail } from '@/types/dependency-tree'
import { transformToD3 } from '@/explorer/transform'
import { resolveNodeStyle } from '@/explorer/nodeStyle'
import { renderNodes, applyNodeStyles } from '@/explorer/renderNodes'
import { renderTreeLinks, applyTreeLinkStyles } from '@/explorer/renderTreeLinks'
import { renderSameVersionLinks, applySameVersionLinkStyles } from '@/explorer/renderSameVersionLinks'
import { TREE_CONFIG } from '@/explorer/config'
import { useHighlightState } from './useHighlightState'
import { useTreeZoom } from './useTreeZoom'

interface UseD3TreeOptions {
  svgRef: Ref<SVGSVGElement | null>
  onNodeSelect: (node: SelectedNodeDetail | null) => void
}

export function useD3Tree(options: UseD3TreeOptions) {
  const { svgRef, onNodeSelect } = options

  // D3 mutable state (not reactive — D3 owns the DOM)
  let root: TreeNode | null = null
  let g: d3.Selection<SVGGElement, unknown, null, undefined> | null = null
  let treeLayout: d3.TreeLayout<D3NodeData> | null = null
  let nameCountMap = new Map<string, number>()

  const highlight = useHighlightState()
  const zoom = useTreeZoom(svgRef)

  function applyHighlights() {
    if (!g || !root) return
    const state = highlight.getState()
    applyNodeStyles(g, state, resolveNodeStyle)
    applyTreeLinkStyles(g, state)
    applySameVersionLinkStyles(g, state)
  }

  function update(source: TreeNode) {
    if (!g || !root || !treeLayout) return
    treeLayout(root)

    const nodes = root.descendants() as TreeNode[]
    const links = root.links()

    nameCountMap = new Map()
    nodes.forEach((d) => nameCountMap.set(d.data.name, (nameCountMap.get(d.data.name) ?? 0) + 1))

    renderSameVersionLinks({ g, nodes, onLinkClick: handleNodeSelect })
    renderTreeLinks({ g, links, source, onLinkClick: (node) => handleNodeSelect(node) })
    renderNodes({ g, nodes, source, onNodeClick: handleClick })

    nodes.forEach((d) => {
      d.x0 = d.x
      d.y0 = d.y
    })

    applyHighlights()
  }

  function handleClick(event: MouseEvent, d: TreeNode) {
    event.stopPropagation()
    if (event.altKey) handleBranchToggle(d)
    else handleNodeSelect(d)
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

  function handleResize() {
    if (!svgRef.value) return
    const container = svgRef.value.parentElement!
    const width = container.offsetWidth
    const height = container.offsetHeight
    d3.select(svgRef.value).attr('width', width).attr('height', height)
    if (g) g.attr('transform', `translate(${TREE_CONFIG.layout.marginLeft},${height / 2})`)
  }

  function initializeTree(data: DependencyNode) {
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

    g = zoomGroup
      .append('g')
      .attr('transform', `translate(${TREE_CONFIG.layout.marginLeft},${height / 2})`)

    treeLayout = d3.tree<D3NodeData>().nodeSize(TREE_CONFIG.layout.nodeSize)
    root = d3.hierarchy(transformToD3(data, new Set([data.name]))) as unknown as TreeNode
    root.x0 = 0
    root.y0 = 0

    update(root)
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
