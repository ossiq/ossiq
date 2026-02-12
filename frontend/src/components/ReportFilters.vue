<script setup lang="ts">
import type { DriftStatus } from '@/composables/useReportFilters'

const searchText = defineModel<string>('searchText', { required: true })
const packageType = defineModel<'all' | 'production' | 'development'>('packageType', { required: true })
const driftStatus = defineModel<DriftStatus | 'all'>('driftStatus', { required: true })
const releaseDistance = defineModel<number | null>('releaseDistance', { required: true })
const timeLag = defineModel<{ min?: number; max?: number } | null>('timeLag', { required: true })

const emit = defineEmits<{
  reset: []
  exportCsv: []
}>()

function onTimeLagChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  if (value === 'all') {
    timeLag.value = null
  } else if (value === 'lt30') {
    timeLag.value = { max: 30 }
  } else if (value === '30-90') {
    timeLag.value = { min: 30, max: 90 }
  } else if (value === 'gt90') {
    timeLag.value = { min: 90 }
  }
}

function onReleaseDistanceChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  releaseDistance.value = value === 'all' ? null : Number(value)
}

function timeLagSelectValue(): string {
  if (timeLag.value === null) return 'all'
  if (timeLag.value.max === 30 && timeLag.value.min === undefined) return 'lt30'
  if (timeLag.value.min === 30 && timeLag.value.max === 90) return '30-90'
  if (timeLag.value.min === 90 && timeLag.value.max === undefined) return 'gt90'
  return 'all'
}
</script>

<template>
  <section class="mb-6">
    <div class="bg-white border border-slate-200 border-b-[3px] border-b-slate-300 px-4 py-3">
      <div class="flex flex-col lg:flex-row lg:items-end gap-4">
        <!-- Search -->
        <div class="flex-1">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1">
            Search
          </label>
          <input
            v-model="searchText"
            type="text"
            placeholder="Filter by dependency name"
            class="w-full h-9 bg-slate-50 border border-slate-200 px-3 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-[#4800E2] focus:border-[#4800E2]"
          />
        </div>

        <!-- Package Types -->
        <div class="w-full sm:w-32">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1">
            Package Types
          </label>
          <select
            v-model="packageType"
            class="w-full h-9 bg-slate-50 border border-slate-200 px-3 text-sm text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4800E2] focus:border-[#4800E2]"
          >
            <option value="all">All</option>
            <option value="production">Production</option>
            <option value="development">Development</option>
          </select>
        </div>

        <!-- Drift Status -->
        <div class="w-full sm:w-32">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1">
            Drift Status
          </label>
          <select
            v-model="driftStatus"
            class="w-full h-9 bg-slate-50 border border-slate-200 px-3 text-sm text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4800E2] focus:border-[#4800E2]"
          >
            <option value="all">All</option>
            <option value="DIFF_MAJOR">Major</option>
            <option value="DIFF_MINOR">Minor</option>
            <option value="DIFF_PATCH">Patch</option>
            <option value="LATEST">Latest</option>
          </select>
        </div>

        <!-- Release Distance -->
        <div class="w-full sm:w-40">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1">
            Release Distance
          </label>
          <select
            :value="releaseDistance === null ? 'all' : String(releaseDistance)"
            class="w-full h-9 bg-slate-50 border border-slate-200 px-3 text-sm text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4800E2] focus:border-[#4800E2]"
            @change="onReleaseDistanceChange"
          >
            <option value="all">All</option>
            <option value="10">&gt; 10 releases</option>
            <option value="100">&gt; 100 releases</option>
            <option value="300">&gt; 300 releases</option>
            <option value="500">&gt; 500 releases</option>
          </select>
        </div>

        <!-- Time Lag -->
        <div class="w-full sm:w-32">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1">
            Time Lag
          </label>
          <select
            :value="timeLagSelectValue()"
            class="w-full h-9 bg-slate-50 border border-slate-200 px-3 text-sm text-slate-900 focus:outline-none focus:ring-1 focus:ring-[#4800E2] focus:border-[#4800E2]"
            @change="onTimeLagChange"
          >
            <option value="all">All</option>
            <option value="lt30">&lt; 30 days</option>
            <option value="30-90">30–90 days</option>
            <option value="gt90">&gt; 90 days</option>
          </select>
        </div>

        <!-- Actions -->
        <div class="flex items-center gap-2 lg:ml-auto pt-1">
          <button
            class="flex items-center h-9 px-3 border border-slate-200 text-sm text-slate-600 hover:bg-slate-50 transition"
            @click="emit('reset')"
          >
            <span class="material-symbols-rounded text-base mr-1">refresh</span>
            Reset
          </button>

          <button
            class="flex items-center h-9 px-4 bg-[#4800E2] hover:bg-[#3a00b8] text-sm text-white font-bold transition"
            @click="emit('exportCsv')"
          >
            Download CSV
            <span class="material-symbols-rounded text-xl ml-1">download</span>
          </button>
        </div>
      </div>
    </div>
  </section>
</template>
