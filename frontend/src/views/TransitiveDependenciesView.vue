<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import { useD3Tree } from '@/composables/useD3Tree'
import DependencyDetailPanel from '@/components/DependencyDetailPanel.vue'
import type { DependencyNode, SelectedNodeDetail } from '@/types/dependency-tree'
import type { OSSIQExportSchemaV11 } from '@/types/report'

const store = useOssiqStore()
const svgRef = ref<SVGSVGElement | null>(null)
const selectedNode = ref<SelectedNodeDetail | null>(null)
const isPanelOpen = ref(false)

function buildDependencyTree(report: OSSIQExportSchemaV11): DependencyNode {
  const root: DependencyNode = {
    name: report.project.name,
    version_installed: 'local',
    dependencies: {},
  }

  for (const pkg of report.production_packages) {
    root.dependencies![pkg.package_name] = {
      name: pkg.package_name,
      version_installed: pkg.installed_version,
      latest_version: pkg.latest_version ?? undefined,
      categories: ['production'],
      dependencies: {},
    }
  }

  if (report.development_packages.length > 0) {
    root.optional_dependencies = {}
    for (const pkg of report.development_packages) {
      root.optional_dependencies[pkg.package_name] = {
        name: pkg.package_name,
        version_installed: pkg.installed_version,
        latest_version: pkg.latest_version ?? undefined,
        categories: ['development'],
        dependencies: {},
      }
    }
  }

  // nodeByPath maps "ancestor1/ancestor2/.../parent" → DependencyNode
  // seeded with direct production deps accessible by their name alone
  const nodeByPath = new Map<string, DependencyNode>()
  for (const [name, node] of Object.entries(root.dependencies!)) {
    nodeByPath.set(name, node)
  }

  // Sort by path length so parents are always registered before their children
  const sorted = [...report.transitive_packages].sort(
    (a, b) => (a.dependency_path?.length ?? 0) - (b.dependency_path?.length ?? 0),
  )

  for (const pkg of sorted) {
    if (!pkg.dependency_path || pkg.dependency_path.length === 0) continue

    const parentPathKey = pkg.dependency_path.join('/')
    const parent = nodeByPath.get(parentPathKey)
    if (!parent) continue

    if (!parent.dependencies) parent.dependencies = {}

    if (!parent.dependencies[pkg.package_name]) {
      const thisNode: DependencyNode = {
        name: pkg.package_name,
        version_installed: pkg.installed_version,
        latest_version: pkg.latest_version ?? undefined,
        dependencies: {},
      }
      parent.dependencies[pkg.package_name] = thisNode
      nodeByPath.set(`${parentPathKey}/${pkg.package_name}`, thisNode)
    }
  }

  return root
}

const dependencyTree = computed<DependencyNode | null>(() =>
  store.report ? buildDependencyTree(store.report) : null,
)

function handleNodeSelect(node: SelectedNodeDetail | null) {
  selectedNode.value = node
  isPanelOpen.value = node !== null
}

function handlePanelClose() {
  selectedNode.value = null
  isPanelOpen.value = false
}

const { initializeTree, zoomIn, zoomOut, resetZoom } = useD3Tree({
  svgRef,
  onNodeSelect: handleNodeSelect,
})

onMounted(() => {
  if (dependencyTree.value) initializeTree(dependencyTree.value)
})

watch(dependencyTree, (tree) => {
  if (tree) nextTick(() => initializeTree(tree))
})
</script>

<template>
  <div v-if="!store.isLoaded" class="flex items-center justify-center py-20">
    <p class="text-sm text-slate-400 uppercase tracking-widest font-bold">Loading report data…</p>
  </div>

  <div v-else class="flex-1 flex w-full">
    <div class="grow relative overflow-hidden bg-white border border-slate-200">
      <header class="absolute top-0 left-0 p-6 z-10 pointer-events-none">
        <h1 class="text-xl font-bold text-slate-900 pointer-events-auto uppercase tracking-tight">
          Transitive Dependencies
        </h1>
        <p class="text-sm text-slate-500 pointer-events-auto">
          Root positioned left. Click nodes for details or to toggle visibility.
        </p>
      </header>

      <div class="absolute bottom-4 right-4 z-10 flex flex-col gap-1">
        <button
          class="w-8 h-8 flex items-center justify-center bg-white border border-slate-300 rounded shadow-sm hover:bg-slate-50 text-slate-700 text-lg font-bold leading-none"
          title="Zoom in"
          @click="zoomIn"
        >
          +
        </button>
        <button
          class="w-8 h-8 flex items-center justify-center bg-white border border-slate-300 rounded shadow-sm hover:bg-slate-50 text-slate-700 text-lg font-bold leading-none"
          title="Zoom out"
          @click="zoomOut"
        >
          &minus;
        </button>
        <button
          class="w-8 h-8 flex items-center justify-center bg-white border border-slate-300 rounded shadow-sm hover:bg-slate-50 text-slate-700 text-xs leading-none"
          title="Reset zoom"
          @click="resetZoom"
        >
          1:1
        </button>
      </div>

      <svg ref="svgRef" class="w-full h-full"></svg>
    </div>

    <DependencyDetailPanel :node="selectedNode" :is-open="isPanelOpen" @close="handlePanelClose" />
  </div>
</template>

<style scoped>
:deep(.node) {
  cursor: pointer;
}

:deep(.node circle) {
  stroke-width: 2.5px;
  transition: all 0.2s;
}

:deep(.node:hover circle) {
  r: 8px;
  filter: brightness(1.1);
}

:deep(.node text) {
  font: 12px sans-serif;
  transition: opacity 0.2s;
}

:deep(.node-label) {
  font-size: 12px;
  font-weight: bold;
  fill: #1e293b;
}

:deep(.version-label) {
  font-size: 10px;
  fill: #64748b;
  font-weight: normal;
}

:deep(.link) {
  fill: none;
  stroke: #cbd5e1;
  stroke-width: 1.5px;
  opacity: 0.6;
  transition: all 0.3s;
}

:deep(.link-duplicate) {
  fill: none;
  stroke: #94a3b8;
  stroke-width: 2px;
  stroke-dasharray: 5, 5;
  opacity: 0.5;
  transition: opacity 0.3s;
}

:deep(.link-duplicate:hover) {
  opacity: 1;
  stroke: #3b82f6;
}

:deep(.collapsed circle) {
  fill-opacity: 0.5 !important;
  stroke-width: 4px !important;
}
</style>
