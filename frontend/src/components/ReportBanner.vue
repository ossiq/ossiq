<script setup lang="ts">
import { computed } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'

const store = useOssiqStore()

const SOURCE_LABELS: Record<string, string> = {
  repositories: 'GitHub (repository info, commits, activity, READMEs)',
  vulnerabilities: 'OSV.dev (vulnerabilities)',
  epss: 'api.first.org (EPSS scores)',
}

const STATUS_LABELS: Record<string, string> = {
  partial: 'partial — some data missing',
  unreachable: 'unreachable — no data',
  rate_limited: 'rate limited — no data',
}

const completeness = computed(() => store.report?.metadata.data_completeness)

// Only the sources that did not come back ok. `overall` is a worst-of across all of them, so a
// clean overall means there is nothing here to draw.
const degraded = computed(() =>
  (completeness.value?.sources ?? []).filter((s) => s.status && s.status !== 'ok'),
)

const warnings = computed(() => store.report?.metadata.warnings ?? [])

const show = computed(
  () =>
    (completeness.value?.overall && completeness.value.overall !== 'ok') ||
    degraded.value.length > 0 ||
    warnings.value.length > 0,
)

function sourceLabel(step: string | undefined): string {
  return (step && SOURCE_LABELS[step]) || step || 'unknown source'
}

function statusLabel(status: string | undefined): string {
  return (status && STATUS_LABELS[status]) || status || 'degraded'
}
</script>

<template>
  <section v-if="show" class="mb-6">
    <div class="border border-amber-300 border-b-[3px] border-b-amber-400 bg-amber-50 p-6">
      <h2 class="text-[10px] font-bold uppercase tracking-widest text-amber-700 mb-3">
        Incomplete data
      </h2>

      <p class="text-sm text-slate-700 leading-relaxed">
        Some data sources did not fully respond, so this report may be based on incomplete data.
        A missing source does not read as a clean result: with vulnerabilities unreachable no CVE
        can be reported, and with GitHub degraded no upstream can be found unmaintained.
      </p>

      <ul v-if="degraded.length" class="mt-4 space-y-1">
        <li
          v-for="source in degraded"
          :key="source.step ?? statusLabel(source.status)"
          class="text-xs text-slate-600"
        >
          <span class="font-bold text-slate-900">{{ sourceLabel(source.step) }}</span>
          <span class="text-amber-700"> — {{ statusLabel(source.status) }}</span>
        </li>
      </ul>

      <ul v-if="warnings.length" class="mt-4 space-y-1">
        <li v-for="(warning, i) in warnings" :key="i" class="text-xs text-slate-600">
          {{ warning }}
        </li>
      </ul>
    </div>
  </section>
</template>
