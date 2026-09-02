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
import type { DependencyTreeRoot, TransitivePackageMetrics } from '@/types/report'

const store = useOssiqStore()
const {
  searchText,
  showAll,
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
    is_prerelease: row.pkg.is_prerelease ?? false,
    is_yanked: row.pkg.is_yanked ?? false,
    is_deprecated: row.pkg.is_deprecated ?? false,
    is_package_unpublished: row.pkg.is_package_unpublished ?? false,
    version_age_days: row.pkg.version_age_days,
    recommended_version: row.pkg.recommended_version ?? null,
    epss: row.pkg.epss ?? null,
    stability_csi: row.pkg.stability_csi ?? null,
    stability_coverage: row.pkg.stability_coverage ?? null,
    stability_risk: row.pkg.stability_risk ?? null,
    maintenance_state: row.pkg.maintenance_state ?? null,
    flow_trend: row.pkg.flow_trend ?? null,
    deprecation_signals: row.pkg.deprecation_signals ?? [],
    deprecation_successor: row.pkg.deprecation_successor ?? null,
    gap_cv: row.pkg.gap_cv ?? null,
    silence_days: row.pkg.silence_days ?? null,
    silence_p: row.pkg.silence_p ?? null,
    commits_sampled: row.pkg.commits_sampled ?? null,
    archived: row.pkg.archived ?? null,
    days_since_push: row.pkg.days_since_push ?? null,
    triage_action: row.pkg.triage_action ?? null,
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
  const treeRoot = store.report?.dependency_tree?.find((r: DependencyTreeRoot) => r.package_name === row.pkg.package_name)
  if (treeRoot) collectSubtree(treeRoot.children)
  if (subtreePackages.length > 0) {
    selectedNode.value.dependencies = Object.fromEntries(
      subtreePackages.map((t: TransitivePackageMetrics) => [t.package_name, { name: t.package_name, version_installed: t.installed_version, cve: t.cve ?? [] }])
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
      <div class="w-full px-4 md:px-6 py-4 space-y-6">
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
            By default the table shows only packages that need action — a version behind, a CVE, or an
            unmaintained upstream. Tick <strong>Show all packages</strong> to see everything.
            <strong>What&rsquo;s Next</strong> is the single next step per package: check for a fix, find or
            consider an alternative, check release notes, or update immediately.
            <strong>Dependency Drift</strong> quantifies the version distance between installed and latest releases,
            segmented by major, minor, and patch changes. This provides a deterministic signal of accumulated change
            and remediation effort across both direct and transitive dependencies.
            <strong>EPSS</strong> is FIRST's probability that a package's worst known CVE sees exploitation in the
            next 30 days; a dash means no CVE carries a score, which is unknown rather than safe.
            <strong>Repository stability</strong> samples the upstream repo's last 100 commits: the gap coefficient
            of variation describes its commit rhythm, and the current silence is compared against that repo's own
            history to tell an unusual quiet from a normal one — evidence, not a verdict. The φi/φp/φa channels add
            issue-resolution, pull-request and engagement responsiveness from a 120-day window; they are advisory
            until calibrated into the Composite Stability Index.
            <strong>Action</strong> crosses the two: exploit pressure decides whether to move now, repository
            activity decides whether to patch or to replace.
          </p>
        </div>

        <!-- Filters -->
        <ReportFilters
          v-model:search-text="searchText"
          v-model:show-all="showAll"
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
