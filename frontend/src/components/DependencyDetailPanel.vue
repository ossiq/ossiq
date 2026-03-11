<script setup lang="ts">
import { computed } from 'vue'
import type { SelectedNodeDetail, DependencyNode } from '@/types/dependency-tree'
import type { CVEInfo } from '@/types/report'
import { computeDriftStatus, formatTimeLag } from '@/composables/useReportFilters'

const props = defineProps<{
  node: SelectedNodeDetail | null
  isOpen: boolean
}>()

const emit = defineEmits<{
  close: []
  selectNode: [name: string]
}>()

const driftStatus = computed(() =>
  props.node ? computeDriftStatus(props.node.version_installed, props.node.latest_version ?? null) : 'LATEST',
)

const lagBarWidth = computed(() => {
  const days = props.node?.time_lag_days
  if (!days || days <= 0) return '0%'
  return `${Math.min(100, Math.round((days / 365) * 100))}%`
})

const lagIsHigh = computed(() => (props.node?.time_lag_days ?? 0) > 90)
const lagIsModerate = computed(() => !lagIsHigh.value && (props.node?.time_lag_days ?? 0) > 30)

const driftConfig: Record<string, { pill: string; icon: string; label: string }> = {
  DIFF_MAJOR: { pill: 'bg-red-700 text-white',        icon: 'flood',   label: 'MAJOR' },
  DIFF_MINOR: { pill: 'bg-yellow-300 text-amber-700', icon: 'warning', label: 'MINOR' },
  DIFF_PATCH: { pill: 'bg-blue-500 text-white',       icon: 'timer',   label: 'PATCH' },
  LATEST:     { pill: 'bg-green-500 text-white',      icon: 'check',   label: 'LATEST' },
}

type SeverityKey = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

const severityStyles: Record<SeverityKey, { card: string; box: string; label: string }> = {
  CRITICAL: { card: 'border-rose-200',  box: 'bg-rose-50 border-rose-100 text-rose-600',    label: 'text-rose-600'  },
  HIGH:     { card: 'border-rose-200',  box: 'bg-rose-50 border-rose-100 text-rose-600',    label: 'text-rose-600'  },
  MEDIUM:   { card: 'border-slate-200', box: 'bg-amber-50 border-amber-100 text-amber-600', label: 'text-amber-600' },
  LOW:      { card: 'border-slate-200', box: 'bg-slate-50 border-slate-200 text-slate-500', label: 'text-slate-500' },
}

function cveStyle(severity: string) {
  return severityStyles[severity as SeverityKey] ?? severityStyles.LOW
}

type TransitiveCVEGroup = { name: string; version: string; cves: CVEInfo[] }

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

function collectTransitiveCVEs(
  deps: Record<string, DependencyNode> | undefined,
  acc: Map<string, TransitiveCVEGroup>,
) {
  if (!deps) return
  for (const child of Object.values(deps)) {
    if (child.cve?.length) {
      const key = `${child.name}@${child.version_installed}`
      if (!acc.has(key)) {
        acc.set(key, { name: child.name, version: child.version_installed, cves: child.cve })
      }
    }
    collectTransitiveCVEs(child.dependencies, acc)
    collectTransitiveCVEs(child.optional_dependencies, acc)
  }
}

const transitiveCVEGroups = computed<TransitiveCVEGroup[]>(() => {
  if (!props.node) return []
  const acc = new Map<string, TransitiveCVEGroup>()
  collectTransitiveCVEs(props.node.dependencies, acc)
  collectTransitiveCVEs(props.node.optional_dependencies, acc)
  const worstSeverity = (g: TransitiveCVEGroup) =>
    Math.min(...g.cves.map(c => SEVERITY_ORDER[c.severity] ?? 99))
  return [...acc.values()].sort((a, b) => worstSeverity(a) - worstSeverity(b))
})

</script>

<template>
  <div
    :class="[
      'flex flex-col bg-white border-l border-slate-200 overflow-hidden shrink-0',
      'transition-all duration-300 ease-out',
      isOpen ? 'w-180' : 'w-0',
    ]"
  >
    <div v-if="node" class="flex flex-col h-full overflow-y-auto w-180">

      <!-- ── Sticky header ── -->
      <div class="sticky top-0 z-10 px-5 py-3.5 bg-white border-b border-slate-200">
        <div class="flex items-start justify-between gap-4">
          <div class="flex items-center gap-3 min-w-0">
            <div class="p-2 bg-white rounded-xl border border-slate-200 shadow-sm shrink-0">
              <span class="material-symbols-rounded text-[24px] leading-none" style="color: #0ea5e9">inventory_2</span>
            </div>
            <div class="min-w-0">
              <h1 class="text-xl font-bold tracking-tight font-mono break-all leading-tight">
                {{ node.name }}
                <span class="text-slate-400 font-normal text-lg ml-1.5">v{{ node.version_installed }}</span>
                <template v-if="node.license && node.license.length > 0">
                  <a
                    :href="`https://spdx.org/licenses/${node.license[0]}.html`"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-sm ml-4 font-mono text-slate-500 hover:text-sky-500 transition-colors inline-flex items-center "
                  >
                  <span class="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-slate-100 text-slate-600 border border-slate-200 hover:bg-sky-50 hover:text-sky-600 hover:border-sky-200 transition-colors">License: {{ node.license[0] }}</span>                  
                </a>
                <span v-if="node.license.length > 1" class="text-sm  py-1 text-slate-400 hover:text-sky-500 transition-colors"> +{{ node.license.length - 1 }}</span>
                  
                </template>
                <span v-else class="text-xs text-slate-400 font-medium italic">License N/A</span>
              </h1>
              <div class="flex flex-wrap items-center gap-2 mt-1.5">
                <span
                  v-for="cat in node.categories ?? ['dependency']"
                  :key="cat"
                  class="px-2 py-0.5 bg-slate-100 text-slate-500 text-[9px] rounded-full border border-slate-200 uppercase font-bold tracking-wide"
                >{{ cat }}</span>
                <span
                  v-if="node.isDuplicate"
                  class="px-2 py-0.5 bg-amber-50 text-amber-600 text-[9px] rounded-full border border-amber-200 uppercase font-bold tracking-wide"
                >Shared Node</span>
                <span class="text-slate-300 select-none">|</span>
                <a
                  v-if="node.package_url"
                  :href="node.package_url"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-sky-500 transition-colors"
                  title="View on registry"
                >
                  <span class="material-symbols-rounded text-sm leading-none">inventory_2</span>
                  Registry
                </a>
                <a
                  v-if="node.repo_url || node.homepage_url"
                  :href="node.repo_url ?? node.homepage_url ?? ''"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-sky-500 transition-colors"
                  title="View repository"
                >
                  <span class="material-symbols-rounded text-sm leading-none">code</span>
                  Repository
                </a>                
              </div>
            </div>
          </div>
          <button
            class="shrink-0 p-2 hover:bg-slate-100 rounded-lg transition-colors text-slate-400 hover:text-slate-700 mt-0.5"
            @click="emit('close')"
          >
            <span class="material-symbols-rounded text-xl leading-none">close</span>
          </button>
        </div>
      </div>

      <!-- ── Content ── -->
      <div class="p-4 space-y-4">

        <!-- Transitive Path -->
        <section
          v-if="node.dependency_path && node.dependency_path.length > 0"
          class="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm"
        >
          <div class="px-4 py-2.5 border-b border-slate-100 bg-slate-50/50">
            <h2 class="text-sm font-bold flex items-center gap-2">
              <span class="material-symbols-rounded text-base leading-none text-slate-500">account_tree</span>
              Transitive Path (Lineage)
            </h2>
          </div>
          <div class="p-4">
            <div class="flex items-center gap-1.5 overflow-x-auto py-1 flex-wrap">
              <!-- Root (not clickable — it's the project root, not a package node) -->
              <div class="px-2 py-1 rounded bg-slate-100 text-[11px] font-bold border border-slate-200 text-slate-500 shrink-0">Root</div>
              <!-- Ancestors -->
              <template v-for="(ancestor, i) in node.dependency_path" :key="i">
                <span class="material-symbols-rounded text-sm leading-none text-slate-300 shrink-0">chevron_right</span>
                <button
                  class="px-2 py-1 rounded bg-slate-100 text-[11px] font-bold border border-slate-200 font-mono text-slate-700 shrink-0 hover:bg-slate-200 hover:border-slate-300 transition-colors cursor-pointer"
                  :title="`Select ${ancestor} in tree`"
                  @click="emit('selectNode', ancestor)"
                >{{ ancestor }}</button>
              </template>
              <!-- Current (not clickable — already selected) -->
              <span class="material-symbols-rounded text-sm leading-none text-slate-300 shrink-0">chevron_right</span>
              <div class="px-2 py-1 rounded bg-sky-50 text-sky-600 text-[11px] font-bold border border-sky-200 font-mono shrink-0">
                {{ node.name }}
              </div>
            </div>
            <p class="mt-3 text-xs text-slate-500 leading-relaxed">
              <strong>Note:</strong> You don't manage
              <code class="font-mono text-sky-500">{{ node.name }}</code> directly — it is pulled in by
              <code class="font-mono">{{ node.dependency_path[node.dependency_path.length - 1] }}</code>.
              Click any ancestor to navigate to it in the tree.
            </p>
          </div>
        </section>

        <!-- Release & Lag -->
        <section class="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
          <div class="px-4 py-2.5 border-b border-slate-100 flex items-center justify-between">
            <h2 class="text-sm font-bold uppercase tracking-wide">Release &amp; Lag</h2>
            <div class="flex items-center gap-2">
              <span class="material-symbols-rounded text-base text-slate-400 leading-none">{{ driftConfig[driftStatus]?.icon ?? 'help' }}</span>
              <span
                class="px-2.5 py-0.5 rounded-full text-xs font-bold"
                :class="driftConfig[driftStatus]?.pill ?? 'bg-slate-200 text-slate-600'"
              >{{ driftConfig[driftStatus]?.label ?? driftStatus }}</span>
            </div>
          </div>
          <div class="p-4">
            <div
              v-if="!node.time_lag_days && !node.releases_lag"
              class="flex items-center gap-2 text-emerald-600 text-sm font-semibold"
            >
              <span class="material-symbols-rounded text-lg leading-none">check_circle</span>
              Up to date
            </div>
            <div v-else class="space-y-3">
              <div class="grid grid-cols-3 gap-2">
                <div class="p-2.5 bg-slate-50 rounded-xl border border-slate-100">
                  <div class="text-[10px] font-bold text-slate-400 uppercase tracking-tighter mb-1">Releases Behind</div>
                  <div class="text-lg font-bold font-mono">{{ node.releases_lag ?? '—' }}</div>
                </div>
                <div class="p-2.5 bg-slate-50 rounded-xl border border-slate-100">
                  <div class="text-[10px] font-bold text-slate-400 uppercase tracking-tighter mb-1">Time Lag</div>
                  <div
                    class="text-lg font-bold font-mono"
                    :class="
                      !node.time_lag_days ? 'text-green-600'
                      : (node.time_lag_days ?? 0) > 730 ? 'text-red-700'
                      : (node.time_lag_days ?? 0) > 365 ? 'text-amber-600'
                      : lagIsHigh ? 'text-rose-500'
                      : lagIsModerate ? 'text-amber-500'
                      : ''
                    "
                  >{{ node.time_lag_days != null ? formatTimeLag(node.time_lag_days) : '—' }}</div>
                </div>
                <div class="p-2.5 bg-slate-50 rounded-xl border border-slate-100">
                  <div class="text-[10px] font-bold text-slate-400 uppercase tracking-tighter mb-1">Latest Version</div>
                  <div class="text-lg font-bold font-mono truncate">{{ node.latest_version || '—' }}</div>
                </div>
              </div>
              <div class="w-full h-1 bg-slate-100 rounded-full overflow-hidden">
                <div
                  :class="['h-full transition-all', lagIsHigh ? 'bg-rose-500' : lagIsModerate ? 'bg-amber-400' : 'bg-emerald-500']"
                  :style="{ width: lagBarWidth }"
                ></div>
              </div>
            </div>
          </div>
        </section>

        <!-- Governance & Constraints -->
        <section class="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
          <div class="px-4 py-2.5 border-b border-slate-100">
            <h2 class="text-sm font-bold uppercase tracking-wide">Governance &amp; Constraints</h2>
          </div>
          <div class="p-4">
            <h3 class="text-xs font-bold text-slate-400 uppercase mb-4">Version Constraint Analysis</h3>
            <div class="space-y-2.5">
              <div class="flex items-center justify-between py-2 border-b border-slate-100">
                <span class="text-sm text-slate-500">Declared range</span>
                <span class="font-mono text-sm bg-slate-100 px-2 py-0.5 rounded text-slate-700">{{ node.version_defined || '—' }}</span>
              </div>
              <div class="flex items-center justify-between py-2 border-b border-slate-100">
                <span class="text-sm text-slate-500">Installed</span>
                <span class="font-mono text-sm bg-blue-50 text-blue-700 px-2 py-0.5 rounded">{{ node.version_installed }}</span>
              </div>
              <div class="flex items-center justify-between py-2">
                <span class="text-sm text-slate-500">Latest available</span>
                <span class="font-mono text-sm bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded">{{ node.latest_version || '—' }}</span>
              </div>
            </div>
            <p class="text-[10px] text-slate-400 italic mt-3">Constraint range visualizer not yet available in this export version.</p>
          </div>
        </section>

        <!-- Security Advisories -->
        <section>
          <div class="flex items-center justify-between mb-3">
            <h2 class="text-base font-bold flex items-center gap-2">
              Security Advisories
              <span
                v-if="node.cve && node.cve.length > 0"
                class="px-2 py-0.5 bg-rose-100 text-rose-600 text-xs rounded-full font-bold"
              >{{ node.cve.length }} Identified</span>
            </h2>
          </div>

          <div
            v-if="!node.cve || node.cve.length === 0"
            class="bg-white rounded-2xl border border-slate-200 p-4 shadow-sm flex items-center gap-2"
          >
            <span class="material-symbols-rounded text-lg leading-none text-emerald-500">verified</span>
            <span class="text-sm font-semibold text-emerald-700">No known vulnerabilities</span>
          </div>

          <div v-else class="space-y-3">
            <div
              v-for="cve in node.cve"
              :key="cve.id"
              :class="['bg-white rounded-2xl border overflow-hidden shadow-sm group hover:shadow-md transition-all', cveStyle(cve.severity).card]"
            >
              <div class="p-4 flex gap-4">
                <div
                  :class="['shrink-0 flex flex-col items-center justify-center w-16 h-16 rounded-xl border', cveStyle(cve.severity).box]"
                >
                  <span class="text-[9px] font-bold uppercase tracking-tighter opacity-70">Sev.</span>
                  <span :class="['text-[11px] font-black text-center leading-tight mt-0.5', cveStyle(cve.severity).label]">
                    {{ cve.severity }}
                  </span>
                </div>
                <div class="grow min-w-0">
                  <div class="flex items-start justify-between gap-3 mb-1">
                    <h3 class="font-bold text-slate-800 text-sm leading-snug break-all">{{ cve.id }}</h3>
                    <span v-if="cve.cve_ids[0] && cve.cve_ids[0] !== cve.id" class="text-xs font-mono text-slate-400 shrink-0">
                      {{ cve.cve_ids[0] }}
                    </span>
                  </div>
                  <p class="text-sm text-slate-500 leading-relaxed mb-3">{{ cve.summary }}</p>
                  <a
                    :href="cve.link"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-xs font-bold text-sky-500 hover:underline inline-flex items-center gap-1"
                  >
                    View Details
                    <span class="material-symbols-rounded text-sm leading-none">open_in_new</span>
                  </a>
                </div>
              </div>
            </div>
          </div>

          <!-- Via Transitive Dependencies -->
          <div v-if="transitiveCVEGroups.length > 0" class="mt-5">
            <div class="flex items-center gap-2 mb-3">
              <h3 class="text-sm font-bold text-slate-600">Via Transitive Dependencies</h3>
              <span class="px-2 py-0.5 bg-slate-100 text-slate-500 text-xs rounded-full font-bold border border-slate-200">
                {{ transitiveCVEGroups.length }}
              </span>
            </div>
            <div class="space-y-3">
              <div
                v-for="group in transitiveCVEGroups"
                :key="`${group.name}@${group.version}`"
                class="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm"
              >
                <!-- Package header -->
                <div class="px-4 py-2.5 bg-slate-50 border-b border-slate-100 flex items-center justify-between gap-3">
                  <div class="flex items-center gap-2 min-w-0">
                    <button
                      class="font-mono text-sm font-bold text-slate-700 hover:text-sky-600 transition-colors truncate text-left"
                      :title="`Navigate to ${group.name}`"
                      @click="emit('selectNode', group.name)"
                    >{{ group.name }}</button>
                    <span class="text-xs font-mono text-slate-400 shrink-0">v{{ group.version }}</span>
                  </div>
                  <span class="px-2 py-0.5 bg-rose-100 text-rose-600 text-xs rounded-full font-bold shrink-0">
                    {{ group.cves.length }}
                  </span>
                </div>
                <!-- CVE list for this package -->
                <div class="divide-y divide-slate-100">
                  <div
                    v-for="cve in group.cves"
                    :key="cve.id"
                    class="p-3 flex gap-3"
                  >
                    <div
                      :class="['shrink-0 flex flex-col items-center justify-center w-12 h-12 rounded-xl border', cveStyle(cve.severity).box]"
                    >
                      <span class="text-[8px] font-bold uppercase tracking-tighter opacity-70">Sev.</span>
                      <span :class="['text-[10px] font-black text-center leading-tight mt-0.5', cveStyle(cve.severity).label]">
                        {{ cve.severity }}
                      </span>
                    </div>
                    <div class="grow min-w-0">
                      <div class="flex items-start justify-between gap-2 mb-0.5">
                        <h4 class="font-bold text-slate-800 text-xs leading-snug break-all">{{ cve.id }}</h4>
                        <span v-if="cve.cve_ids[0] && cve.cve_ids[0] !== cve.id" class="text-[10px] font-mono text-slate-400 shrink-0">
                          {{ cve.cve_ids[0] }}
                        </span>
                      </div>
                      <p class="text-xs text-slate-500 leading-relaxed mb-2">{{ cve.summary }}</p>
                      <a
                        :href="cve.link"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="text-xs font-bold text-sky-500 hover:underline inline-flex items-center gap-1"
                      >
                        View Details
                        <span class="material-symbols-rounded text-sm leading-none">open_in_new</span>
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- License -->
        <section class="bg-white rounded-2xl border border-slate-200 p-4 shadow-sm">
          <h3 class="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">License</h3>
          <div v-if="node.license && node.license.length > 0" class="flex flex-wrap gap-2">
            <a
              v-for="lic in node.license"
              :key="lic"
              :href="`https://spdx.org/licenses/${lic}.html`"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-slate-100 text-slate-600 border border-slate-200 hover:bg-sky-50 hover:text-sky-600 hover:border-sky-200 transition-colors"
            >{{ lic }}</a>
          </div>
          <p v-else class="text-[10px] text-slate-400 italic">License data not available.</p>
        </section>

      </div>
    </div>
  </div>
</template>
