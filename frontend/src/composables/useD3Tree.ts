import { ref, onMounted, onUnmounted, type Ref } from 'vue'
import * as d3 from 'd3'
import type { DependencyNode, D3NodeData, CrossLink, TreeNode, SelectedNodeDetail } from '@/types/dependency-tree'

interface UseD3TreeOptions {
  svgRef: Ref<SVGSVGElement | null>
  onNodeSelect: (node: SelectedNodeDetail | null) => void
}

export function useD3Tree(options: UseD3TreeOptions) {
  const { svgRef, onNodeSelect } = options

  const colorScale = d3.scaleOrdinal(d3.schemeTableau10)
  const discoveredPackages = new Set<string>()
  const crossLinks = ref<CrossLink[]>([])

  let root: TreeNode | null = null
  let g: d3.Selection<SVGGElement, unknown, null, undefined> | null = null
  let treeLayout: d3.TreeLayout<D3NodeData> | null = null

  function transformToD3(node: DependencyNode): D3NodeData {
    const children: D3NodeData[] = []
    if (node.dependencies) {
      Object.entries(node.dependencies).forEach(([, dep]) => {
        if (discoveredPackages.has(dep.name)) {
          crossLinks.value.push({
            parentName: node.name,
            targetName: dep.name,
            targetData: dep,
          })
        } else {
          discoveredPackages.add(dep.name)
          children.push(transformToD3(dep))
        }
      })
    }
    return { ...node, children: children.length > 0 ? children : null }
  }

  function update(source: TreeNode) {
    if (!g || !root || !treeLayout) return

    treeLayout(root)

    const nodes = root.descendants() as TreeNode[]
    const links = root.links()

    const nodePositionMap = new Map<string, TreeNode>()
    nodes.forEach((d) => nodePositionMap.set(d.data.name, d))

    // --- LINKS ---
    const link = g
      .selectAll<SVGPathElement, d3.HierarchyLink<D3NodeData>>('.link')
      .data(links, (d) => d.target.data.name)

    const linkEnter = link
      .enter()
      .insert('path', 'g')
      .attr('class', 'link')
      .attr('d', () => {
        const o = { x: source.x0 ?? 0, y: source.y0 ?? 0 }
        return d3
          .linkHorizontal<unknown, { x: number; y: number }>()
          .x((p) => p.y)
          .y((p) => p.x)({ source: o, target: o })
      })

    linkEnter
      .merge(link)
      .transition()
      .duration(500)
      .attr(
        'd',
        d3
          .linkHorizontal<d3.HierarchyLink<D3NodeData>, d3.HierarchyPointNode<D3NodeData>>()
          .x((d) => d.y)
          .y((d) => d.x) as unknown as string,
      )

    link
      .exit()
      .transition()
      .duration(500)
      .attr('d', () => {
        const o = { x: source.x, y: source.y }
        return d3
          .linkHorizontal<unknown, { x: number; y: number }>()
          .x((p) => p.y)
          .y((p) => p.x)({ source: o, target: o })
      })
      .remove()

    // --- CROSS LINKS (Duplicates) ---
    const crossLink = g
      .selectAll<SVGPathElement, CrossLink>('.link-duplicate')
      .data(crossLinks.value, (d) => `${d.parentName}-${d.targetName}`)

    crossLink
      .enter()
      .insert('path', 'g')
      .attr('class', 'link-duplicate')
      .merge(crossLink)
      .transition()
      .duration(500)
      .attr('d', (d) => {
        const s = nodePositionMap.get(d.parentName)
        const t = nodePositionMap.get(d.targetName)
        if (!s || !t) return null
        return d3
          .linkHorizontal<unknown, { x: number; y: number }>()
          .x((p) => p.y)
          .y((p) => p.x)({ source: { x: s.x, y: s.y }, target: { x: t.x, y: t.y } })
      })
      .style('opacity', (d) => {
        return nodePositionMap.has(d.parentName) && nodePositionMap.has(d.targetName) ? 0.5 : 0
      })

    crossLink.exit().remove()

    // --- NODES ---
    const node = g
      .selectAll<SVGGElement, TreeNode>('.node')
      .data(nodes, (d) => d.data.name)

    const nodeEnter = node
      .enter()
      .append('g')
      .attr('class', (d) => `node ${d._children ? 'collapsed' : ''}`)
      .attr('transform', () => `translate(${source.y0 ?? 0},${source.x0 ?? 0})`)
      .on('click', (_event: MouseEvent, d: TreeNode) => handleNodeClick(d))

    nodeEnter
      .append('circle')
      .attr('r', 6)
      .attr('fill', (d) => colorScale(d.data.name))
      .attr('stroke', (d) => d3.rgb(colorScale(d.data.name)).darker().toString())

    nodeEnter
      .append('text')
      .attr('dy', '-0.6em')
      .attr('x', 12)
      .text((d) => d.data.name)
      .attr('class', 'node-label')

    nodeEnter
      .append('text')
      .attr('dy', '1.1em')
      .attr('x', 12)
      .text((d) => `v${d.data.version_installed}`)
      .attr('class', 'version-label')

    const nodeUpdate = nodeEnter.merge(node)

    nodeUpdate
      .transition()
      .duration(500)
      .attr('transform', (d) => `translate(${d.y},${d.x})`)

    nodeUpdate
      .select('circle')
      .attr('fill-opacity', (d) => (d._children ? 0.4 : 1))
      .attr('stroke-width', (d) => (d._children ? 4 : 2))

    node
      .exit()
      .transition()
      .duration(500)
      .attr('transform', () => `translate(${source.y},${source.x})`)
      .remove()

    nodes.forEach((d) => {
      d.x0 = d.x
      d.y0 = d.y
    })
  }

  function handleNodeClick(d: TreeNode) {
    if (d._clickCycle === 0) {
      if (d._children) {
        ;(d as d3.HierarchyPointNode<D3NodeData>).children = d._children as unknown as d3.HierarchyPointNode<D3NodeData>[]
        d._children = undefined
      }
      const isDuplicated = crossLinks.value.some((cl) => cl.targetName === d.data.name)
      onNodeSelect({
        name: d.data.name,
        version_installed: d.data.version_installed,
        version_defined: d.data.version_defined,
        latest_version: d.data.latest_version,
        categories: d.data.categories,
        isDuplicate: isDuplicated,
      })
      d._clickCycle = 1
    } else if (d._clickCycle === 1) {
      onNodeSelect(null)
      d._clickCycle = 2
    } else {
      if (d.children) {
        d._children = d.children as unknown as TreeNode[]
        ;(d as d3.HierarchyPointNode<D3NodeData>).children = undefined
      }
      d._clickCycle = 0
    }
    update(d)
  }

  function initializeTree(data: DependencyNode) {
    if (!svgRef.value) return

    discoveredPackages.clear()
    crossLinks.value = []

    discoveredPackages.add(data.name)
    const transformedData = transformToD3(data)

    const container = svgRef.value.parentElement!
    const width = container.offsetWidth
    const height = container.offsetHeight
    const margin = { left: 100 }

    const svg = d3.select(svgRef.value).attr('width', width).attr('height', height)

    svg.selectAll('*').remove()

    const zoomGroup = svg.append('g')

    svg.call(
      d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 3])
        .on('zoom', (event) => {
          zoomGroup.attr('transform', event.transform.toString())
        }),
    )

    g = zoomGroup.append('g').attr('transform', `translate(${margin.left},${height / 2})`)

    treeLayout = d3.tree<D3NodeData>().nodeSize([60, 220])
    root = d3.hierarchy(transformedData) as unknown as TreeNode
    root.x0 = 0
    root.y0 = 0

    ;(root.descendants() as TreeNode[]).forEach((d) => {
      d._clickCycle = 0
    })

    update(root)
  }

  function handleResize() {
    if (!svgRef.value) return
    const container = svgRef.value.parentElement!
    const width = container.offsetWidth
    const height = container.offsetHeight

    d3.select(svgRef.value).attr('width', width).attr('height', height)

    if (g) {
      g.attr('transform', `translate(100,${height / 2})`)
    }
  }

  onMounted(() => {
    window.addEventListener('resize', handleResize)
  })

  onUnmounted(() => {
    window.removeEventListener('resize', handleResize)
  })

  return {
    initializeTree,
  }
}
