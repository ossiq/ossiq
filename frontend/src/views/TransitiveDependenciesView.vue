<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import { useD3Tree } from '@/composables/useD3Tree'
import { useTreeFilters } from '@/composables/useTreeFilters'
import DependencyDetailPanel from '@/components/DependencyDetailPanel.vue'
import type { DependencyNode, SelectedNodeDetail } from '@/types/dependency-tree'
import type { OSSIQExportSchemaV13, PackageMetrics, TransitivePackageMetrics, DependencyPath } from '@/types/report'

const store = useOssiqStore()
const svgRef = ref<SVGSVGElement | null>(null)
const selectedNode = ref<SelectedNodeDetail | null>(null)
const isPanelOpen = ref(false)
const showLegend = ref(false)

function buildDependencyTree(report: OSSIQExportSchemaV13): DependencyNode {
  // Build a map of package name → highest CVE severity
  const severityRank: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
  const cveMap = new Map<string, string>()
  for (const pkg of [...report.production_packages, ...report.development_packages, ...report.transitive_packages]) {
    if (!pkg.cve.length) continue
    const maxSev = pkg.cve.reduce((best: typeof pkg.cve[0], c: typeof pkg.cve[0]) =>
      (severityRank[c.severity] ?? 0) > (severityRank[best.severity] ?? 0) ? c : best,
    ).severity
    const existing = cveMap.get(pkg.package_name)
    if (!existing || (severityRank[maxSev] ?? 0) > (severityRank[existing] ?? 0)) {
      cveMap.set(pkg.package_name, maxSev)
    }
  }

  const root: DependencyNode = {
    name: report.project.name,
    version_installed: 'local',
    dependencies: {},
  }

  const buildDirectNodeDetail = (pkg: PackageMetrics, categories: string[]) => ({
    categories,
    name: pkg.package_name,
    version_installed: pkg.installed_version,
    version_defined: pkg.version_constraint ?? undefined,
    latest_version: pkg.latest_version ?? undefined,
    severity: cveMap.get(pkg.package_name),
    time_lag_days: pkg.time_lag_days,
    releases_lag: pkg.releases_lag,
    cve: pkg.cve,
    repo_url: pkg.repo_url,
    homepage_url: pkg.homepage_url,
    package_url: pkg.package_url,
    dependencies: {},
    license: pkg.license,
    purl: pkg.purl,
    dependency_path: pkg.dependency_path,
    constraint_type: pkg.constraint_type ?? null,
    constraint_source_file: pkg.constraint_source_file ?? null,
    extras: pkg.extras ?? null,
  })

  const buildTransitiveNodeDetail = (pkg: TransitivePackageMetrics, dp: DependencyPath, categories: string[]) => ({
    categories,
    name: pkg.package_name,
    version_installed: pkg.installed_version,
    version_defined: dp.version_constraint ?? undefined,
    latest_version: pkg.latest_version ?? undefined,
    severity: cveMap.get(pkg.package_name),
    time_lag_days: pkg.time_lag_days,
    releases_lag: pkg.releases_lag,
    cve: pkg.cve,
    repo_url: pkg.repo_url,
    homepage_url: pkg.homepage_url,
    package_url: pkg.package_url,
    dependencies: {},
    license: pkg.license,
    purl: pkg.purl,
    dependency_path: dp.path,
    constraint_type: dp.constraint_type ?? null,
    constraint_source_file: dp.constraint_source_file ?? null,
    extras: dp.extras ?? null,
  })

  for (const pkg of report.production_packages) {
    root.dependencies![pkg.package_name] = buildDirectNodeDetail(pkg, ['production'])
  }

  if (report.development_packages.length > 0) {
    root.optional_dependencies = {}
    for (const pkg of report.development_packages) {
      root.optional_dependencies[pkg.package_name] = buildDirectNodeDetail(pkg, ['development'])
    }
  }

  // nodeByPath maps "ancestor1/ancestor2/.../parent" → DependencyNode
  // seeded with direct production deps accessible by their name alone
  const nodeByPath = new Map<string, DependencyNode>()
  for (const [name, node] of Object.entries(root.dependencies!)) {
    nodeByPath.set(name, node)
  }

  // Expand deduplicated transitive packages back to per-path records,
  // then sort by path length so parents are always registered before their children
  const expanded: Array<{ pkg: TransitivePackageMetrics; dp: DependencyPath }> = []
  for (const pkg of report.transitive_packages) {
    for (const dp of pkg.dependency_paths) {
      expanded.push({ pkg, dp })
    }
  }
  expanded.sort((a, b) => a.dp.path.length - b.dp.path.length)

  for (const { pkg, dp } of expanded) {
    if (dp.path.length === 0) continue

    const parentPathKey = dp.path.join('/')
    const parent = nodeByPath.get(parentPathKey)
    if (!parent) continue

    if (!parent.dependencies) parent.dependencies = {}

    if (!parent.dependencies[pkg.package_name]) {
      const thisNode: DependencyNode = buildTransitiveNodeDetail(pkg, dp, ['transitive'])
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

const { searchQuery, filterCve, filterNarrowed, filterOverridePinned, filteredTree, hasActiveFilters, clearFilters } =
  useTreeFilters({ dependencyTree })

const { initializeTree, selectNodeByName, zoomIn, zoomOut, resetZoom } = useD3Tree({
  svgRef,
  onNodeSelect: handleNodeSelect,
})

onMounted(() => {
  if (filteredTree.value) initializeTree(filteredTree.value)
})

watch(filteredTree, (tree) => {
  if (tree) nextTick(() => initializeTree(tree))
})
</script>

<template>
  <div v-if="!store.isLoaded" class="flex items-center justify-center py-20">
    <p class="text-sm text-slate-400 uppercase tracking-widest font-bold">Loading report data…</p>
  </div>

  <div v-else class="flex-1 flex w-full">
    <div class="grow relative overflow-hidden bg-white border border-slate-200">
      <header
        class="absolute top-0 left-0 right-0 px-6 pt-5 pb-4 z-10 flex items-start justify-between gap-4 pointer-events-none"
      >
        <div class="pointer-events-auto">
          <h1 class="text-xl font-bold text-slate-900 uppercase tracking-tight">Transitive Dependencies</h1>
          <p class="text-sm text-slate-500 mt-0.5">Root positioned left. Click for details · Alt+Click to fold/unfold branch.</p>
        </div>

        <div class="flex items-center gap-2 mt-1 pointer-events-auto">
          <!-- Search -->
          <div class="relative">
            <span
              class="material-symbols-rounded absolute left-2 top-1/2 -translate-y-1/2 text-slate-400 text-base select-none"
            >search</span>
            <input
              v-model="searchQuery"
              type="text"
              placeholder="Search packages…"
              class="h-8 w-56 bg-white/90 border border-slate-200 pl-7 pr-3 text-sm text-slate-900 placeholder-slate-400 rounded focus:outline-none focus:ring-1 focus:ring-[#4800E2] focus:border-[#4800E2]"
            />
          </div>

          <!-- CVE toggle -->
          <button
            :class="[
              'h-7 px-2.5 flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide rounded-full border transition-all',
              filterCve
                ? 'bg-[#DE4514] border-[#DE4514] text-white'
                : 'bg-white border-slate-200 text-slate-500 hover:bg-slate-50 hover:border-slate-300',
            ]"
            @click="filterCve = !filterCve"
          >
            <span class="material-symbols-rounded text-sm leading-none">security</span>
            CVE
          </button>

          <!-- Narrowed toggle -->
          <button
            :class="[
              'h-7 px-2.5 flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide rounded-full border transition-all',
              filterNarrowed
                ? 'bg-[#a16207] border-[#a16207] text-white'
                : 'bg-white border-slate-200 text-slate-500 hover:bg-slate-50 hover:border-slate-300',
            ]"
            @click="filterNarrowed = !filterNarrowed"
          >
            <span class="material-symbols-rounded text-sm leading-none">arrow_range</span>
            Narrowed
          </button>

          <!-- Override/Pinned toggle -->
          <button
            :class="[
              'h-7 px-2.5 flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide rounded-full border transition-all',
              filterOverridePinned
                ? 'bg-[#ea580c] border-[#ea580c] text-white'
                : 'bg-white border-slate-200 text-slate-500 hover:bg-slate-50 hover:border-slate-300',
            ]"
            @click="filterOverridePinned = !filterOverridePinned"
          >
            <span class="material-symbols-rounded text-sm leading-none">push_pin</span>
            Override/Pinned
          </button>

          <!-- Clear filters -->
          <button
            v-if="hasActiveFilters"
            class="h-7 px-2.5 flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide rounded-full border transition-all bg-slate-100 border-slate-300 text-slate-600 hover:bg-slate-200"
            title="Clear all filters"
            @click="clearFilters"
          >
            <span class="material-symbols-rounded text-sm leading-none">close</span>
            Clear
          </button>

          <!-- Legend toggle -->
          <button
            :class="[
              'h-7 w-7 flex items-center justify-center rounded-full border transition-all',
              showLegend
                ? 'bg-slate-700 border-slate-700 text-white'
                : 'bg-white border-slate-200 text-slate-500 hover:bg-slate-50 hover:border-slate-300',
            ]"
            title="Show legend"
            @click="showLegend = !showLegend"
          >
            <span class="material-symbols-rounded text-sm leading-none">info</span>
          </button>
        </div>

        <!-- Legend panel -->
        <div
          v-if="showLegend"
          class="absolute top-18 right-6 z-20 pointer-events-auto w-64 bg-white border border-slate-200 rounded-lg shadow-md p-3 text-xs text-slate-700 space-y-3"
        >
          <div class="flex items-center justify-between">
            <span class="font-semibold text-slate-900 uppercase tracking-wide text-[10px]">Legend</span>
            <button class="text-slate-400 hover:text-slate-700 leading-none" @click="showLegend = false">
              <span class="material-symbols-rounded text-base leading-none">close</span>
            </button>
          </div>

          <!-- Color coding -->
          <div>
            <p class="font-semibold text-[10px] uppercase tracking-wide text-slate-500 mb-1.5">Node colors</p>
            <div class="space-y-1.5">
              <div class="flex items-center gap-2">
                <span class="inline-flex items-center justify-center w-4 h-4 rounded-full shrink-0 text-[8px] font-bold" style="background:#fecaca; outline:2px solid #dc2626; outline-offset:-1px">!</span>
                <span><strong class="text-slate-800">CVE detected</strong> — known vulnerability</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="inline-block w-4 h-4 rounded-full shrink-0" style="background:#fef08a; outline:2px dashed #a16207; outline-offset:-1px"></span>
                <span><strong class="text-slate-800">Narrowed</strong> — bounded range (e.g. <code>&lt;y</code>)</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="inline-block w-4 h-4 rounded-full shrink-0" style="background:#ffedd5; outline:3px solid #c2410c; outline-offset:-1px"></span>
                <span><strong class="text-slate-800">Pinned</strong> — exact version (e.g. <code>1.2.3</code>)</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="inline-block w-4 h-4 rounded-full shrink-0" style="background:#fed7aa; outline:3px dashed #ea580c; outline-offset:-1px"></span>
                <span><strong class="text-slate-800">Override</strong> — forced version replacement</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="inline-block w-4 h-4 rounded-full shrink-0" style="background:#bbf7d0; outline:2px dotted #16a34a; outline-offset:-1px"></span>
                <span><strong class="text-slate-800">Additive</strong> — external constraint file</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="inline-block w-4 h-4 rounded-full shrink-0" style="background:#bfdbfe; outline:2px solid #1d4ed8; outline-offset:-1px"></span>
                <span><strong class="text-slate-800">Default</strong> — no specific concern</span>
              </div>
            </div>
          </div>

          <!-- Interactions -->
          <div>
            <p class="font-semibold text-[10px] uppercase tracking-wide text-slate-500 mb-1.5">Interactions</p>
            <ul class="space-y-1 text-slate-600 leading-snug">
              <li>Click a <strong>tree edge</strong> → selects the child node</li>
              <li>Click a <strong>dashed line</strong> → selects the connected duplicate</li>
              <li><strong>Alt+Click</strong> a node → fold / unfold subtree</li>
              <li>Click <strong>background</strong> → exit focus mode</li>
            </ul>
          </div>

          <!-- Duplicates -->
          <div>
            <p class="font-semibold text-[10px] uppercase tracking-wide text-slate-500 mb-1.5">Duplicate packages</p>
            <p class="text-slate-600 leading-snug">
              Dashed curved lines connect nodes sharing the same <em>name@version</em> across different subtrees. Clicking any one highlights all occurrences.
            </p>
          </div>
        </div>
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

    <DependencyDetailPanel :node="selectedNode" :is-open="isPanelOpen" @close="handlePanelClose" @select-node="selectNodeByName" />
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
  stroke-width: 2.5px;
  opacity: 0.7;
  transition: all 0.3s;
}

:deep(.link-same-version) {
  fill: none;
  stroke: #94a3b8;
  stroke-width: 1px;
  stroke-dasharray: 4, 6;
  opacity: 0.3;
  pointer-events: none;
}
</style>
