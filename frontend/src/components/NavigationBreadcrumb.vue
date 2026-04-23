<script setup lang="ts">
import type { NavFrame } from '@/types/registry'

defineProps<{ projectName: string; stack: NavFrame[] }>()

const emit = defineEmits<{
  jumpToRoot: []
  jumpTo: [index: number]
}>()
</script>

<template>
  <nav
    class="flex items-center gap-1 px-6 py-2 text-sm overflow-x-auto shrink-0 bg-white border-b border-slate-100 select-none"
    aria-label="Dependency navigation"
  >
    <button
      class="text-slate-500 hover:text-slate-900 hover:underline transition-colors whitespace-nowrap"
      @click="emit('jumpToRoot')"
    >
      {{ projectName }}
    </button>

    <template v-for="(frame, index) in stack" :key="index">
      <span class="text-slate-300 shrink-0" aria-hidden="true">›</span>
      <span
        v-if="index === stack.length - 1"
        class="font-semibold text-slate-900 truncate"
        aria-current="page"
      >
        {{ frame.label }}
      </span>
      <button
        v-else
        class="text-slate-500 hover:text-slate-900 hover:underline transition-colors whitespace-nowrap"
        @click="emit('jumpTo', index)"
      >
        {{ frame.label }}
      </button>
    </template>
  </nav>
</template>
