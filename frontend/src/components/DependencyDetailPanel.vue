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

const severityStyles: Record<SeverityKey, { card: string; box: string; label: string; badge: string; accent: string }> = {
  CRITICAL: { card: 'border-rose-200',  box: 'bg-rose-50 border-rose-100 text-rose-600',    label: 'text-rose-600',  badge: 'text-rose-600 bg-rose-50 border-rose-200',    accent: 'border-rose-500'  },
  HIGH:     { card: 'border-rose-200',  box: 'bg-rose-50 border-rose-100 text-rose-600',    label: 'text-rose-600',  badge: 'text-rose-600 bg-rose-50 border-rose-200',    accent: 'border-rose-500'  },
  MEDIUM:   { card: 'border-slate-200', box: 'bg-amber-50 border-amber-100 text-amber-600', label: 'text-amber-600', badge: 'text-amber-600 bg-amber-50 border-amber-200', accent: 'border-amber-400' },
  LOW:      { card: 'border-slate-200', box: 'bg-slate-50 border-slate-200 text-slate-500', label: 'text-slate-500', badge: 'text-slate-600 bg-slate-50 border-slate-200', accent: 'border-slate-300' },
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
      'flex flex-col bg-white border-l border-slate-200 shrink-0 overflow-none overflow-x-scroll',
      'transition-all duration-300 ease-out',
      isOpen ? 'w-180' : 'w-0',
    ]"
  >
    <div v-if="node" class="flex flex-col">

      <!-- ── Sticky header ── -->
      <div class="sticky top-0 z-10 px-5 py-4 bg-white border-b border-slate-100">
        <div class="flex items-start justify-between gap-4">
          <div class="min-w-0 space-y-1">
            <!-- Category badges -->
            <div class="flex flex-wrap items-center gap-1">
              <span
                v-for="cat in node.categories ?? ['dependency']"
                :key="cat"
                class="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-white bg-black"
              >{{ cat }}</span>
              <span
                v-if="node.isDuplicate"
                class="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-amber-700 bg-amber-100 border border-amber-200"
              >Shared Node</span>
              <span
                v-if="node.is_package_unpublished"
                class="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-red-700 bg-red-100 border border-red-300"
              >Unpublished</span>
              <span
                v-else-if="node.is_yanked"
                class="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-red-700 bg-red-100 border border-red-300"
              >Yanked</span>
              <span
                v-else-if="node.is_deprecated"
                class="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-yellow-700 bg-yellow-100 border border-yellow-300"
              >Deprecated</span>
              <span
                v-else-if="node.is_prerelease"
                class="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest text-amber-700 bg-amber-100 border border-amber-300"
              >Pre-release</span>
            </div>
            <!-- Package name + version -->
            <h1 class="text-2xl font-bold tracking-tight leading-none font-mono break-all">
              {{ node.name }}
              <span class="text-sky-600 font-medium opacity-60 text-xl ml-1">{{ node.version_installed }}</span>
            </h1>
            <!-- License + links -->
            <div class="flex flex-wrap items-center gap-2 pt-0.5">
              <template v-if="node.license && node.license.length > 0">
                <a
                  v-for="lic in node.license"
                  :key="lic"
                  :href="`https://spdx.org/licenses/${lic}.html`"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-[9px] font-bold font-mono text-slate-500 border border-slate-200 px-1.5 py-0.5 hover:text-sky-500 hover:border-sky-200 transition-colors"
                >{{ lic }}</a>
              </template>
              <span v-else class="text-[9px] font-mono text-slate-400 italic">License N/A</span>
              <span v-if="node.package_url || node.repo_url || node.homepage_url" class="text-slate-200 select-none">·</span>
              <a
                v-if="node.package_url"
                :href="node.package_url"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex items-center gap-0.5 text-[9px] font-bold text-slate-400 hover:text-sky-500 transition-colors uppercase tracking-wide"
              >
                <span class="material-symbols-rounded text-xs leading-none">inventory_2</span>
                Registry
              </a>
              <a
                v-if="node.repo_url || node.homepage_url"
                :href="node.repo_url ?? node.homepage_url ?? ''"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex items-center gap-0.5 text-[9px] font-bold text-slate-400 hover:text-sky-500 transition-colors uppercase tracking-wide"
              >
                <span class="material-symbols-rounded text-xs leading-none">code</span>
                Repo
              </a>
            </div>
          </div>
          <button
            class="shrink-0 text-center align-middle transition-colors text-slate-300 hover:text-slate-700"
            @click="emit('close')"
          >
            <span class="material-symbols-rounded text-xl leading-none cursor-pointer">close</span>
          </button>
        </div>
      </div>

      <!-- ── Scrollable body ── -->
      <div class="flex-1 overflow-y-auto px-5 py-6 space-y-8">

        <!-- State Analysis -->
        <section>
          <div class="flex items-center justify-between mb-3">
            <p class="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono">Drift Status</p>
            <span
              class="px-2 py-0.5 text-[10px] font-bold"
              :class="driftConfig[driftStatus]?.pill ?? 'bg-slate-200 text-slate-600'"
            >{{ driftConfig[driftStatus]?.label ?? driftStatus }}</span>
          </div>
          <div
            v-if="!node.time_lag_days && !node.releases_lag"
            class="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-600"
          >
            <span class="w-2 h-2 bg-emerald-500 rounded-full shrink-0"></span>
            Up to date
          </div>
          <div v-else class="border-t border-slate-100 pt-4 space-y-4">
            <div class="grid grid-cols-3 gap-4">
              <div class="space-y-0.5">
                <p class="text-[10px] font-bold text-slate-400 uppercase">Time Lag</p>
                <p
                  class="text-xl font-bold font-mono"
                  :class="
                    !node.time_lag_days ? 'text-green-600'
                    : (node.time_lag_days ?? 0) > 730 ? 'text-red-700'
                    : (node.time_lag_days ?? 0) > 365 ? 'text-amber-600'
                    : lagIsHigh ? 'text-rose-500'
                    : lagIsModerate ? 'text-amber-500'
                    : ''
                  "
                >{{ node.time_lag_days != null ? formatTimeLag(node.time_lag_days) : '—' }}</p>
              </div>
              <div class="space-y-0.5">
                <p class="text-[10px] font-bold text-slate-400 uppercase">Releases</p>
                <p class="text-xl font-bold font-mono">
                  {{ node.releases_lag ?? '—' }}
                  <span v-if="node.releases_lag" class="text-xs ml-0.5 text-slate-400 font-normal">revs</span>
                </p>
              </div>
              <div class="space-y-0.5">
                <p class="text-[10px] font-bold text-slate-400 uppercase">Latest Version</p>
                <p class="text-sm font-bold font-mono text-slate-700 truncate">{{ node.latest_version || '—' }}</p>
              </div>
            </div>
            <div class="w-full h-1 bg-slate-100">
              <div
                :class="['h-full transition-all', lagIsHigh ? 'bg-rose-500' : lagIsModerate ? 'bg-amber-400' : 'bg-emerald-500']"
                :style="{ width: lagBarWidth }"
              ></div>
            </div>
          </div>
        </section>

        <!-- Dependency Goggles -->
        <section v-if="node.dependency_path && node.dependency_path.length > 0">
          <p class="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono mb-3">Dependency Goggles</p>
          <div class="bg-slate-50 border border-slate-100 border-l-2 border-l-sky-400 p-3 font-mono text-[11px] space-y-1.5">
            <div class="flex items-center gap-2 text-slate-400">
              <span class="text-sky-400">→</span>
              <span>root</span>
            </div>
            <div
              v-for="(ancestor, i) in node.dependency_path"
              :key="i"
              class="flex items-center gap-2 text-slate-400"
              :style="{ paddingLeft: `${(i + 1) * 12}px` }"
            >
              <span class="text-slate-300 shrink-0">└─</span>
              <button
                class="hover:text-sky-600 transition-colors text-left truncate cursor-pointer"
                :title="`Navigate to ${ancestor}`"
                @click="emit('selectNode', ancestor)"
              >{{ ancestor }}</button>
            </div>
            <div
              class="flex items-center gap-2 font-bold text-sky-600"
              :style="{ paddingLeft: `${(node.dependency_path.length + 1) * 12}px` }"
            >
              <span class="text-sky-400 shrink-0">└─</span>
              <span class="truncate cursor-pointer">{{ node.name }}</span>
            </div>
          </div>
        </section>

        <!-- Policy Compliance -->
        <section>
          <p class="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono mb-2">Policy Compliance</p>
          <div class="border-t border-slate-100 divide-y divide-slate-100">
            <div class="flex items-center justify-between py-2">
              <span class="text-[10px] text-slate-400 uppercase">Constraint</span>
              <span class="text-[10px] font-mono font-bold text-slate-700">{{ node.version_defined || '—' }}</span>
            </div>
            <div class="flex items-center justify-between py-2">
              <span class="text-[10px] text-slate-400 uppercase">Resolved</span>
              <span class="text-[10px] font-mono font-bold text-sky-600">{{ node.version_installed }}</span>
            </div>
            <div class="flex items-center justify-between py-2">
              <span class="text-[10px] text-slate-400 uppercase">Latest</span>
              <span class="text-[10px] font-mono font-bold text-emerald-600">{{ node.latest_version || '—' }}</span>
            </div>
            <div
              v-if="node.constraint_type && node.constraint_type !== 'DECLARED'"
              class="flex items-center justify-between py-2"
            >
              <span class="text-[10px] text-slate-400 uppercase">Constraint Type</span>
              <span
                class="text-[10px] font-mono font-bold"
                :class="{
                  'text-fuchsia-700': node.constraint_type === 'OVERRIDE',
                  'text-purple-700': node.constraint_type === 'ADDITIVE',
                  'text-red-600':    node.constraint_type === 'NARROWED',
                  'text-yellow-700': node.constraint_type === 'PINNED',
                }"
              >
                {{ node.constraint_type }}
                <span v-if="node.constraint_source_file" class="font-normal text-slate-400">
                  via {{ node.constraint_source_file }}
                </span>
              </span>
            </div>
            <div
              v-if="node.extras && node.extras.length > 0"
              class="flex items-center justify-between py-2"
            >
              <span class="text-[10px] text-slate-400 uppercase">Extras</span>
              <div class="flex flex-wrap gap-1 justify-end">
                <span
                  v-for="extra in node.extras"
                  :key="extra"
                  class="text-[9px] font-mono font-bold px-1.5 py-0.5 bg-sky-50 text-sky-700 border border-sky-200"
                >{{ extra }}</span>
              </div>
            </div>
          </div>
        </section>

        <!-- Security Advisories -->
        <section>
          <div class="flex items-center gap-2 mb-3">
            <p class="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono">Security Advisories</p>
            <span
              v-if="node.cve && node.cve.length > 0"
              class="px-2 py-0.5 bg-rose-100 text-rose-600 text-[9px] font-bold rounded-full"
            >{{ node.cve.length }}</span>
          </div>

          <div
            v-if="!node.cve || node.cve.length === 0"
            class="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-600"
          >
            <span class="w-2 h-2 bg-emerald-500 rounded-full shrink-0"></span>
            No known vulnerabilities
          </div>

          <div v-else class="divide-y divide-slate-100">
            <div v-for="cve in node.cve" :key="cve.id" class="py-2">
              <div class="flex items-center gap-2 mb-1">
                <span :class="['text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase shrink-0', cveStyle(cve.severity).badge]">{{ cve.severity }}</span>
                <a
                  :href="cve.link"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="font-mono text-[10px] text-sky-600 font-bold inline-flex items-center gap-0.5"
                >
                  <span class="hover:underline">{{ cve.id }}</span>
                  <span class="material-symbols-rounded leading-none hover:no-underline text-slate-400" style="font-size:14px">open_in_new</span>
                </a>
                <span class="bg-slate-100 px-1 rounded text-[8px] font-medium text-slate-600 border border-slate-200 uppercase ml-auto shrink-0">{{ cve.source }}</span>
              </div>
              <p class="text-[11px] text-slate-500 leading-snug">{{ cve.summary }}</p>
            </div>
          </div>

          <!-- Via Transitive Dependencies -->
          <div v-if="transitiveCVEGroups.length > 0" class="mt-6">
            <div class="flex items-center gap-2 mb-3">
              <p class="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono">Via Transitive Dependencies</p>
              <span class="px-2 py-0.5 bg-slate-100 text-slate-500 text-[9px] font-bold rounded-full border border-slate-200">{{ transitiveCVEGroups.length }}</span>
            </div>
            <div class="space-y-5 divide-y divide-slate-100">
              <div v-for="group in transitiveCVEGroups" :key="`${group.name}@${group.version}`">
                <div class="flex items-center gap-2 mb-0">
                  <button
                    class="font-mono text-[11px] font-bold text-slate-700 hover:text-sky-600 transition-colors text-left truncate cursor-pointer"
                    :title="`Navigate to ${group.name}`"
                    @click="emit('selectNode', group.name)"
                  >{{ group.name }}</button>
                  <span class="text-[10px] font-mono text-slate-400 shrink-0">v{{ group.version }}</span>
                  <span class="px-1.5 py-0.5 bg-rose-100 text-rose-600 text-[9px] font-bold rounded-full ml-auto shrink-0">{{ group.cves.length }}</span>
                </div>
                <div class="divide-y divide-slate-100">
                  <div v-for="cve in group.cves" :key="cve.id" class="py-1">
                    <div class="flex items-center gap-2 mb-1">
                      <span :class="['text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase shrink-0', cveStyle(cve.severity).badge]">{{ cve.severity }}</span>
                      <a
                        :href="cve.link"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="font-mono text-[10px] text-sky-600 font-bold inline-flex items-center gap-0.5"
                      >
                        <span class="hover:underline">{{ cve.id }}</span>
                        <span class="material-symbols-rounded leading-none hover:no-underline text-slate-400" style="font-size:14px">open_in_new</span>
                      </a>
                      <span class="bg-slate-100 px-1 rounded text-[8px] font-medium text-slate-600 border border-slate-200 uppercase ml-auto shrink-0">{{ cve.source }}</span>
                    </div>
                    <p class="text-[11px] text-slate-500 leading-snug">{{ cve.summary }}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- License -->
        <section>
          <p class="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono mb-2">License</p>
          <div v-if="node.license && node.license.length > 0" class="flex flex-wrap gap-2">
            <a
              v-for="lic in node.license"
              :key="lic"
              :href="`https://spdx.org/licenses/${lic}.html`"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center px-2 py-0.5 text-[9px] font-bold font-mono bg-slate-100 text-slate-600 border border-slate-200 hover:bg-sky-50 hover:text-sky-600 hover:border-sky-200 transition-colors"
            >{{ lic }}</a>
          </div>
          <p v-else class="text-[10px] text-slate-400 italic">License data not available.</p>
        </section>

      </div>
    </div>
  </div>
</template>
