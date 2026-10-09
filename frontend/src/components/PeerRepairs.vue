<script setup lang="ts">
import { computed } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'

const store = useOssiqStore()

// Absent in a report made before schema 1.6 and empty for PyPI projects or a tree whose peers all
// resolve; both draw nothing.
const repairs = computed(() => store.report?.peer_repairs ?? [])
</script>

<template>
  <section v-if="repairs.length" class="mb-6" data-testid="peer-repairs">
    <div class="border border-sky-200 border-b-[3px] border-b-sky-400 bg-sky-50 p-6">
      <h2 class="text-[10px] font-bold uppercase tracking-widest text-sky-700 mb-3">
        Peer repairs
      </h2>

      <p class="text-sm text-slate-700 leading-relaxed">
        Some packages declare a peer dependency that is installed, but only out of their reach, so
        npm will not load it for them. Adding the peer to the manifest places it where they resolve
        it; <span class="font-mono">ossiq apply</span> does this and moves the stale copies of its
        family along with it.
      </p>

      <ul class="mt-4 space-y-3">
        <li v-for="repair in repairs" :key="repair.package_name" class="text-xs text-slate-600">
          <div class="flex flex-wrap items-baseline gap-x-2">
            <span class="font-mono font-bold text-slate-900">
              {{ repair.package_name }} {{ repair.suggested_constraint }}
            </span>
            <span class="text-[10px] font-bold uppercase tracking-wide text-sky-700">
              {{ repair.is_dev_dependency ? 'devDependency' : 'dependency' }}
            </span>
            <span>
              for <span class="font-mono">{{ repair.requirers.join(', ') }}</span>
            </span>
          </div>
          <ul v-if="repair.family_moves?.length" class="mt-1 ml-4 space-y-0.5 font-mono text-[11px]">
            <li v-for="move in repair.family_moves" :key="`${move.package_name}@${move.current_version}`">
              {{ move.package_name }}
              <span class="text-slate-400">{{ move.current_version }}</span>
              <span class="text-slate-300 mx-1">→</span>
              <span class="text-violet-700">{{ move.projected_version }}</span>
            </li>
          </ul>
        </li>
      </ul>
    </div>
  </section>
</template>
