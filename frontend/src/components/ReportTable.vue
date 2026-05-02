<script setup lang="ts">
import type { ReportRow, SortColumn, SortDirection } from '@/composables/useReportFilters'
import { constraintCircleClasses } from '@/explorer/nodeStyle'

defineProps<{
  rows: ReportRow[]
  sortColumn: SortColumn | null
  sortDirection: SortDirection
  registry: string
}>()

const emit = defineEmits<{
  sort: [column: SortColumn]
  selectPackage: [row: ReportRow]
}>()

interface ColumnDef {
  id: SortColumn
  label: string
  width?: string
}

const columns: ColumnDef[] = [
  { id: 'name',      label: 'Dependency',   width: '18%' },
  { id: 'cve',       label: 'Security',     width: '8%'  },
  { id: 'drift',     label: 'Drift Status', width: '12%' },
  { id: 'installed', label: 'Installed',    width: '8%'  },
  { id: 'latest',    label: 'Latest',       width: '8%'  },
  { id: 'releases',  label: 'Releases',     width: '8%'  },
  { id: 'timeLag',   label: 'Time Lag',     width: '8%'  },
  { id: 'versionAge', label: 'Version Age', width: '8%'  },
]

function sortIcon(col: SortColumn, currentCol: SortColumn | null, dir: SortDirection): string {
  if (currentCol !== col || dir === 'none') return 'sort_by_alpha'
  return dir === 'asc' ? 'arrow_upward' : 'arrow_downward'
}

function driftIcon(status: string): string {
  switch (status) {
    case 'DIFF_MAJOR': return 'flood'
    case 'DIFF_MINOR': return 'warning'
    case 'DIFF_PATCH': return 'timer'
    case 'LATEST': return 'check'
    default: return 'help'
  }
}

function driftLabel(status: string): string {
  switch (status) {
    case 'DIFF_MAJOR': return 'MAJOR'
    case 'DIFF_MINOR': return 'MINOR'
    case 'DIFF_PATCH': return 'PATCH'
    case 'LATEST': return 'LATEST'
    default: return status
  }
}

function driftClasses(status: string): string {
  switch (status) {
    case 'DIFF_MAJOR': return 'bg-red-700 text-white'
    case 'DIFF_MINOR': return 'bg-yellow-300 text-amber-700'
    case 'DIFF_PATCH': return 'bg-blue-500 text-white'
    case 'LATEST': return 'bg-green-500 text-white'
    default: return 'bg-slate-200 text-slate-600'
  }
}

function timeLagColor(days: number | null): string {
  if (days === null || days === 0) return 'text-green-600'
  if (days > 730) return 'text-red-700'
  if (days > 365) return 'text-amber-600'
  return ''
}

function osvUrl(packageName: string, ecosystem: string): string {
  const eco = ecosystem === 'npm' ? 'npm' : 'PyPI'
  return `https://osv.dev/list?q=${encodeURIComponent(packageName)}&ecosystem=${eco}`
}

function spdxUrl(spdxId: string): string {
  return `https://spdx.org/licenses/${spdxId}.html`
}
</script>

<template>
  <section>
    <div class="overflow-hidden bg-white border border-slate-200 border-b-[3px] border-b-slate-300">
      <table class="min-w-full text-left border-collapse">
        <thead class="bg-slate-50 border-b border-slate-200">
          <tr>
            <th
              v-for="col in columns"
              :key="col.id"
              :width="col.width"
              class="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-slate-500"
            >
              <span class="flex items-center gap-2">
                <span>{{ col.label }}</span>
                <button
                  class="material-symbols-rounded text-xl text-slate-400 hover:text-slate-700 transition"
                  @click="emit('sort', col.id)"
                >
                  {{ sortIcon(col.id, sortColumn, sortDirection) }}
                </button>
              </span>
            </th>
            <th class="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-slate-500" width="12%">License</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100">
          <tr
            v-for="row in rows"
            :key="row.pkg.package_name"
            class="hover:bg-slate-50 transition-colors"
          >
            <!-- Dependency -->
            <td class="px-6 py-3">
              <div class="flex items-center gap-2">
                <span
                  class="inline-block w-5 h-5 rounded-full shrink-0"
                  :class="constraintCircleClasses(row.pkg.constraint_type)"
                  :title="row.pkg.constraint_type ?? 'DECLARED'"
                ></span>
                <button
                  class="text-[#4800E2] hover:underline font-medium text-left cursor-pointer"
                  @click="emit('selectPackage', row)"
                >{{ row.pkg.package_name }}</button>
                <span
                  v-if="row.hasTransitiveCve"
                  class="text-orange-500 font-black leading-none"
                  title="Has transitive dependency CVEs"
                >*</span>
                <span
                  v-if="row.isDev"
                  class="material-symbols-rounded text-xl text-slate-400"
                  title="Development dependency"
                >logo_dev</span>
              </div>
            </td>

            <!-- Security -->
            <td class="px-6 py-3 text-center">
              <a
                v-if="row.cveCount > 0"
                :href="osvUrl(row.pkg.package_name, registry)"
                target="_blank"
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold text-white bg-[#DE4514]"
              >
                <span class="material-symbols-rounded text-base">security</span>
                {{ row.cveCount }} CVE{{ row.cveCount > 1 ? 's' : '' }}
              </a>
            </td>

            <!-- Drift Status -->
            <td class="px-6 py-3">
              <div class="flex items-center gap-2">
                <span class="material-symbols-rounded text-xl text-slate-400">{{ driftIcon(row.driftStatus) }}</span>
                <span
                  class="px-3 py-1 rounded-full text-sm font-bold"
                  :class="driftClasses(row.driftStatus)"
                >{{ driftLabel(row.driftStatus) }}</span>
              </div>
            </td>

            <!-- Installed -->
            <td class="px-6 py-3 text-sm text-slate-800">
              <span class="font-mono">{{ row.pkg.installed_version }}</span>
              <span
                v-if="row.isPackageUnpublished"
                class="ml-1.5 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide bg-red-100 text-red-700 border border-red-300 rounded"
              >unpublished</span>
              <span
                v-else-if="row.isYanked"
                class="ml-1.5 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide bg-red-100 text-red-700 border border-red-300 rounded"
              >yanked</span>
              <span
                v-else-if="row.isDeprecated"
                class="ml-1.5 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide bg-yellow-100 text-yellow-700 border border-yellow-300 rounded"
              >deprecated</span>
              <span
                v-else-if="row.isPrerelease"
                class="ml-1.5 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide bg-amber-100 text-amber-700 border border-amber-300 rounded"
              >pre</span>
            </td>

            <!-- Latest -->
            <td class="px-6 py-3 text-sm">{{ row.pkg.latest_version ?? '—' }}</td>

            <!-- Releases Distance -->
            <td class="px-6 py-3 text-sm">{{ row.pkg.releases_lag ?? 0 }}</td>

            <!-- Time Lag -->
            <td class="px-6 py-3">
              <strong
                class="font-semibold"
                :class="timeLagColor(row.pkg.time_lag_days)"
              >{{ row.timeLagDisplay }}</strong>
            </td>

            <!-- Version Age -->
            <td class="px-6 py-3">
              <strong
                class="font-semibold"
                :class="timeLagColor(row.pkg.version_age_days)"
              >{{ row.versionAgeDisplay }}</strong>
            </td>

            <!-- License -->
            <td class="px-6 py-3">
              <div class="flex flex-wrap gap-1">
                <template v-if="row.license.length > 0">
                  <a
                    :href="spdxUrl(row.license[0])"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-100 text-slate-600 hover:text-sky-600 transition-colors border border-slate-200"
                  >{{ row.license[0] }}</a>
                  <span v-if="row.license.length > 1" class="text-[10px] text-slate-400 self-center">+{{ row.license.length - 1 }}</span>
                </template>
                <span v-else class="text-xs text-slate-300">—</span>
              </div>
            </td>
          </tr>

          <tr v-if="rows.length === 0">
            <td colspan="9" class="px-6 py-8 text-center text-sm text-slate-400">
              No dependencies match the current filters.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
