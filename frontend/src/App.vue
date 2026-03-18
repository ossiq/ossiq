<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'
import { useReportLoader } from '@/composables/useReportLoader'

useReportLoader()

const route = useRoute()
const isFullscreen = computed(() => route.meta.layout === 'fullscreen')
</script>

<template>
  <div class="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
    <!-- Header -->
    <header class="w-full bg-white border-b border-slate-200">
      <div class="max-w-7xl mx-auto flex items-stretch justify-between px-6" style="min-height: 60px;">
        <div class="flex items-center gap-2 py-4">
          <a href="https://ossiq.dev"><img src="/src/styles/oss-iq-logo.svg" alt="OSS IQ" class="w-26"></a>
        </div>

        <nav class="flex items-center gap-8 h-full self-center">
          <RouterLink to="/" class="nav-link text-sm font-medium text-slate-500 hover:text-black">
            Scan Report
          </RouterLink>
          <RouterLink to="/transitive-dependencies" class="nav-link text-sm font-medium text-slate-500 hover:text-black">
            Transitive Dependencies
          </RouterLink>
        </nav>

        <a
          href="https://github.com/nickstenning/ossiq/"
          target="_blank"
          class="flex items-center gap-1 text-slate-600 hover:text-black transition font-medium text-sm py-4"
        >
          <span class="material-symbols-rounded text-xl">code</span>
          <span>GitHub</span>
        </a>
      </div>
    </header>

    <!-- Main Content -->
    <main :class="isFullscreen ? 'flex-1 w-full flex flex-col' : 'flex-grow max-w-7xl mx-auto p-4 md:p-6 w-full'">
      <RouterView />
    </main>

    <!-- Footer (hidden in fullscreen layout) -->
    <footer v-if="!isFullscreen" class="mt-auto border-t border-slate-200 bg-white py-6">
      <div class="max-w-7xl mx-auto px-6 text-center space-y-1">
        <p class="text-xs text-slate-400">
          Released under the
          <a
            href="https://www.gnu.org/licenses/agpl-3.0.html"
            target="_blank"
            class="underline hover:text-slate-600 transition"
          >AGPLv3 license.</a>
        </p>
        <p class="text-xs text-slate-400">
          &copy; 2025 OSS IQ
        </p>
      </div>
    </footer>
  </div>
</template>

<style>
body {
  font-family: 'Instrument Sans', sans-serif;
  margin: 0;
}

.nav-link {
  display: inline-flex;
  align-items: center;
  padding-bottom: 2px;
  border-bottom: 2px solid transparent;
  transition: color 0.15s, border-color 0.15s;
}

.nav-link.router-link-active {
  color: #0f172a;
  border-bottom-color: #4800E2;
}
</style>
