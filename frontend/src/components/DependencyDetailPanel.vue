<script setup lang="ts">
import type { SelectedNodeDetail } from '@/types/dependency-tree'

defineProps<{
  node: SelectedNodeDetail | null
  isOpen: boolean
}>()

const emit = defineEmits<{
  close: []
}>()
</script>

<template>
  <div
    :class="[
      'fixed right-0 top-0 h-full w-80 bg-white shadow-2xl border-l border-slate-200 z-50 flex flex-col',
      'transition-transform duration-300 ease-out',
      isOpen ? 'translate-x-0' : 'translate-x-full',
    ]"
  >
    <div class="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50">
      <h2 class="font-bold text-slate-800">Package Details</h2>
      <button @click="emit('close')" class="p-2 hover:bg-slate-200 rounded-full transition-colors">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="20"
          height="20"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="M18 6 6 18M6 6l12 12" />
        </svg>
      </button>
    </div>

    <div v-if="node" class="p-6 space-y-6 overflow-y-auto">
      <div>
        <label class="text-[10px] uppercase tracking-wider text-slate-400 font-bold">Package Name</label>
        <div class="text-xl font-bold text-slate-900 break-all">{{ node.name }}</div>
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div class="bg-blue-50 p-3 rounded-lg border border-blue-100">
          <label class="text-[10px] uppercase text-blue-600 font-bold block mb-1">Installed</label>
          <span class="text-lg font-mono font-bold">{{ node.version_installed }}</span>
        </div>
        <div class="bg-emerald-50 p-3 rounded-lg border border-emerald-100">
          <label class="text-[10px] uppercase text-emerald-600 font-bold block mb-1">Latest</label>
          <span class="text-lg font-mono font-bold">{{ node.latest_version || 'N/A' }}</span>
        </div>
      </div>

      <div>
        <label class="text-[10px] uppercase tracking-wider text-slate-400 font-bold block mb-2">Details</label>
        <div class="text-sm text-slate-600 py-2 border-b border-slate-100 flex justify-between">
          <span>Range:</span>
          <span class="font-mono bg-slate-100 px-1 rounded">{{ node.version_defined || 'Inherited' }}</span>
        </div>
        <div class="flex flex-wrap gap-1 mt-3">
          <span
            v-for="category in node.categories || ['dependency']"
            :key="category"
            class="px-2 py-0.5 bg-slate-100 text-slate-600 text-[9px] rounded-full border border-slate-200 uppercase font-bold"
          >
            {{ category }}
          </span>
        </div>
      </div>

      <div v-if="node.isDuplicate" class="bg-amber-50 border border-amber-200 p-4 rounded-lg">
        <div class="flex gap-2 text-amber-800">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="18"
            height="18"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="m17 2 4 4-4 4" />
            <path d="M3 11v-1a4 4 0 0 1 4-4h14" />
            <path d="m7 22-4-4 4-4" />
            <path d="M21 13v1a4 4 0 0 1-4 4H3" />
          </svg>
          <span class="text-xs font-bold">Shared Node</span>
        </div>
        <p class="text-[11px] text-amber-700 mt-1">Found in multiple branches of the tree.</p>
      </div>
    </div>
  </div>
</template>
