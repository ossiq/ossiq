import type { Ref } from 'vue'
import * as d3 from 'd3'
import { TREE_CONFIG } from '@/explorer/config'

/**
 * Manages D3 zoom/pan behavior for the dependency tree SVG.
 * Attach once via `initZoom(zoomGroup)` after SVG setup; then use zoomIn/Out/reset freely.
 */
export function useTreeZoom(svgRef: Ref<SVGSVGElement | null>) {
  let zoomBehavior: d3.ZoomBehavior<SVGSVGElement, unknown> | null = null

  /** Attach zoom/pan behavior to the SVG. Call once per tree initialization. */
  function initZoom(zoomGroup: d3.Selection<SVGGElement, unknown, null, undefined>) {
    if (!svgRef.value) return

    zoomBehavior = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent(TREE_CONFIG.zoom.scaleExtent)
      .on('zoom', (event) => {
        zoomGroup.attr('transform', event.transform.toString())
      })

    const svg = d3.select(svgRef.value)
    svg.call(zoomBehavior)
    svg.style('cursor', 'grab')
    svg.on('mousedown.cursor', () => svg.style('cursor', 'grabbing'))
    svg.on('mouseup.cursor', () => svg.style('cursor', 'grab'))
  }

  function zoomIn() {
    if (!svgRef.value || !zoomBehavior) return
    d3.select(svgRef.value)
      .transition()
      .duration(TREE_CONFIG.zoom.transitionDuration)
      .call(zoomBehavior.scaleBy, TREE_CONFIG.zoom.stepFactor)
  }

  function zoomOut() {
    if (!svgRef.value || !zoomBehavior) return
    d3.select(svgRef.value)
      .transition()
      .duration(TREE_CONFIG.zoom.transitionDuration)
      .call(zoomBehavior.scaleBy, 1 / TREE_CONFIG.zoom.stepFactor)
  }

  function resetZoom() {
    if (!svgRef.value || !zoomBehavior) return
    d3.select(svgRef.value)
      .transition()
      .duration(TREE_CONFIG.zoom.transitionDuration)
      .call(zoomBehavior.scaleTo, 1)
  }

  return { initZoom, zoomIn, zoomOut, resetZoom }
}
