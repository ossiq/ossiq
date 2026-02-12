<script setup lang="ts">
import { computed, ref } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import { useReportFilters } from '@/composables/useReportFilters'
import { useCsvExport } from '@/composables/useCsvExport'
import ReportFilters from '@/components/ReportFilters.vue'
import ReportTable from '@/components/ReportTable.vue'
import ReportLegend from '@/components/ReportLegend.vue'

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
const { exportCsv } = useCsvExport()

const showHelp = ref(false)

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

function handleExportCsv() {
  exportCsv(sortedRows.value)
}
</script>

<template>
  <div v-if="!store.isLoaded" class="flex items-center justify-center py-20">
    <p class="text-sm text-slate-400 uppercase tracking-widest font-bold">Loading report data…</p>
  </div>

  <div v-else class="space-y-6">
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
      @export-csv="handleExportCsv"
    />

    <!-- Table -->
    <ReportTable
      :rows="sortedRows"
      :sort-column="sortColumn"
      :sort-direction="sortDirection"
      :registry="registry"
      @sort="toggleSort"
    />

    <!-- Legend -->
    <ReportLegend />
  </div>
</template>
