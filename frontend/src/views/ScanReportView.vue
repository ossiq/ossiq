<script setup lang="ts">
import { computed, ref } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import { useReportFilters } from '@/composables/useReportFilters'
import type { ReportRow } from '@/composables/useReportFilters'
import ReportFilters from '@/components/ReportFilters.vue'
import ReportTable from '@/components/ReportTable.vue'
import ReportLegend from '@/components/ReportLegend.vue'
import DependencyDetailPanel from '@/components/DependencyDetailPanel.vue'
import type { SelectedNodeDetail } from '@/types/dependency-tree'

const store = useOssiqStore()
const {
  searchText,
  packageTypeFilter,
  driftStatusFilter,
  releaseDistanceFilter,
  timeLagFilter,
  sortColumn,
  sortDirection,
  sortedRows,
  toggleSort,
  resetFilters,
} = useReportFilters()

const showHelp = ref(false)
const selectedNode = ref<SelectedNodeDetail | null>(null)
const isPanelOpen = ref(false)

const registry = computed(() => store.report?.project.registry ?? 'npm')
const projectName = computed(() => store.report?.project.name ?? '')
const exportTimestamp = computed(() => {
  const ts = store.report?.metadata.export_timestamp
  if (!ts) return { date: '', time: '' }
  const d = new Date(ts)
  const date = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  const time = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'UTC' }) + ' UTC'
  return { date, time }
})

function handleSelectPackage(row: ReportRow) {
  selectedNode.value = {
    name: row.pkg.package_name,
    version_installed: row.pkg.installed_version,
    version_defined: row.pkg['version_constraint'] as string | undefined,
    latest_version: row.pkg.latest_version ?? undefined,
    categories: row.isDev ? ['development'] : ['production'],
    isDuplicate: false,
    time_lag_days: row.pkg.time_lag_days,
    releases_lag: row.pkg.releases_lag,
    cve: row.pkg.cve,
    dependency_path: row.pkg.dependency_path,
    repo_url: row.pkg.repo_url,
    homepage_url: row.pkg.homepage_url,
    package_url: row.pkg.package_url,
    license: row.pkg?.license ?? null,
    purl: row.pkg.purl ?? null,
    constraint_type: row.pkg.constraint_type ?? null,
    constraint_source_file: row.pkg.constraint_source_file ?? null,
    extras: row.pkg.extras ?? null,
  }

  const transitives = store.report?.transitive_packages ?? []
  const subtreePackages: typeof transitives = []
  function collectSubtree(nodes: NonNullable<typeof store.report>['dependency_tree'][number]['children']) {
    for (const node of nodes ?? []) {
      const pkg = transitives[node.ref]
      if (pkg) subtreePackages.push(pkg)
      collectSubtree(node.children)
    }
  }
  const treeRoot = store.report?.dependency_tree?.find(r => r.package_name === row.pkg.package_name)
  if (treeRoot) collectSubtree(treeRoot.children)
  if (subtreePackages.length > 0) {
    selectedNode.value.dependencies = Object.fromEntries(
      subtreePackages.map(t => [t.package_name, { name: t.package_name, version_installed: t.installed_version, cve: t.cve ?? [] }])
    )
  }

  isPanelOpen.value = true
}

function handlePanelClose() {
  selectedNode.value = null
  isPanelOpen.value = false
}
</script>

<template>
  <div v-if="!store.isLoaded" class="flex items-center justify-center py-20">
    <p class="text-sm text-slate-400 uppercase tracking-widest font-bold">Loading report data…</p>
  </div>

  <div v-else class="flex-1 flex w-full overflow-hidden">
    <!-- Main scrollable content -->
    <div class="flex-1 overflow-y-auto">
      <div class="max-w-7xl mx-auto p-4 md:p-6 space-y-6">
        <!-- Header -->
        <div class="flex justify-between items-start">
          <div class="flex flex-col justify-center">
            <div class="flex items-start gap-1">
              <h1 class="text-2xl md:text-3xl font-bold tracking-tight uppercase leading-none">
                Dependency Drift <span class="text-slate-400">Report</span>
              </h1>
              <button
                class="p-1 hover:opacity-75 transition"
                @click="showHelp = !showHelp"
              >
                <span class="material-symbols-rounded text-2xl">info</span>
              </button>
            </div>
          </div>

          <div class="flex flex-col items-end gap-4">
            <div class="flex items-center gap-4">
              <span class="inline-flex items-center px-3 py-1 bg-black text-white text-[10px] font-bold uppercase tracking-widest">
                Project
              </span>
              <span class="text-xl font-medium tracking-tight">{{ projectName }}</span>
            </div>
            <div class="flex flex-col items-end">
              <span class="text-xl font-light">{{ exportTimestamp.date }}</span>
              <span class="font-mono text-sm font-bold text-black bg-yellow-300 px-1 mt-1">
                {{ exportTimestamp.time }}
              </span>
            </div>
          </div>
        </div>

        <!-- Help text -->
        <div v-if="showHelp" class="w-3/4">
          <p class="text-sm text-slate-500">
            <strong>Dependency Drift</strong> quantifies the version distance between installed and latest releases,
            segmented by major, minor, and patch changes. This provides a deterministic signal of accumulated change
            and remediation effort across both direct and transitive dependencies.
          </p>
        </div>

        <!-- Filters -->
        <ReportFilters
          v-model:search-text="searchText"
          v-model:package-type="packageTypeFilter"
          v-model:drift-status="driftStatusFilter"
          v-model:release-distance="releaseDistanceFilter"
          v-model:time-lag="timeLagFilter"
          @reset="resetFilters"
        />

        <!-- Table -->
        <ReportTable
          :rows="sortedRows"
          :sort-column="sortColumn"
          :sort-direction="sortDirection"
          :registry="registry"
          @sort="toggleSort"
          @select-package="handleSelectPackage"
        />

        <!-- Legend -->
        <ReportLegend />
      </div>
    </div>

    <!-- Detail Panel -->
    <DependencyDetailPanel :node="selectedNode" :is-open="isPanelOpen" @close="handlePanelClose" />
  </div>
</template>
