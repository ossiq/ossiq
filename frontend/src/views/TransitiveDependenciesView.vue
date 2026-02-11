<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useD3Tree } from '@/composables/useD3Tree'
import DependencyDetailPanel from '@/components/DependencyDetailPanel.vue'
import type { DependencyNode, SelectedNodeDetail } from '@/types/dependency-tree'

const svgRef = ref<SVGSVGElement | null>(null)
const selectedNode = ref<SelectedNodeDetail | null>(null)
const isPanelOpen = ref(false)

const sampleData: DependencyNode = {
  name: 'enterprise-app',
  version_installed: '2.4.0',
  latest_version: '3.0.0',
  categories: ['root'],
  dependencies: {
    react: {
      name: 'react',
      version_installed: '18.2.0',
      version_defined: '^18.2.0',
      latest_version: '18.2.0',
      categories: ['ui-library'],
      dependencies: {
        'loose-envify': {
          name: 'loose-envify',
          version_installed: '1.4.0',
          dependencies: {
            'js-tokens': { name: 'js-tokens', version_installed: '4.0.0' },
          },
        },
      },
    },
    express: {
      name: 'express',
      version_installed: '4.18.2',
      version_defined: '^4.17.1',
      latest_version: '5.0.0',
      categories: ['framework'],
      dependencies: {
        'body-parser': {
          name: 'body-parser',
          version_installed: '1.20.1',
          dependencies: {
            qs: { name: 'qs', version_installed: '6.11.0' },
            debug: { name: 'debug', version_installed: '2.6.9' },
          },
        },
        finalhandler: {
          name: 'finalhandler',
          version_installed: '1.2.0',
          dependencies: {
            debug: { name: 'debug', version_installed: '2.6.9' },
          },
        },
      },
    },
    typescript: {
      name: 'typescript',
      version_installed: '5.1.6',
      version_defined: '^5.0.0',
      latest_version: '5.3.3',
      categories: ['build-tool'],
      dependencies: {
        tslib: { name: 'tslib', version_installed: '2.6.2' },
      },
    },
    axios: {
      name: 'axios',
      version_installed: '1.6.0',
      version_defined: '^1.6.0',
      latest_version: '1.6.2',
      categories: ['http-client'],
      dependencies: {
        'follow-redirects': { name: 'follow-redirects', version_installed: '1.15.2' },
        'form-data': { name: 'form-data', version_installed: '4.0.0' },
      },
    },
    ajv: {
      name: 'ajv',
      version_installed: '8.12.0',
      version_defined: '^8.0.0',
      latest_version: '8.12.0',
      categories: ['validation'],
      dependencies: {
        'fast-deep-equal': { name: 'fast-deep-equal', version_installed: '3.1.3' },
        'json-schema-traverse': { name: 'json-schema-traverse', version_installed: '1.0.0' },
      },
    },
    jest: {
      name: 'jest',
      version_installed: '29.7.0',
      latest_version: '30.0.0',
      categories: ['testing'],
      dependencies: {
        'jest-core': {
          name: 'jest-core',
          version_installed: '29.7.0',
          dependencies: {
            'jest-util': { name: 'jest-util', version_installed: '29.7.0' },
          },
        },
        chalk: { name: 'chalk', version_installed: '4.1.2' },
      },
    },
    lodash: { name: 'lodash', version_installed: '4.17.21', categories: ['utility'] },
    zod: { name: 'zod', version_installed: '3.22.4', categories: ['validation'] },
    vite: {
      name: 'vite',
      version_installed: '5.0.0',
      categories: ['build-tool'],
      dependencies: {
        esbuild: { name: 'esbuild', version_installed: '0.19.0' },
        postcss: { name: 'postcss', version_installed: '8.4.31' },
        rollup: { name: 'rollup', version_installed: '4.3.0' },
      },
    },
    helmet: {
      name: 'helmet',
      version_installed: '7.1.0',
      categories: ['security'],
      dependencies: {
        qs: { name: 'qs', version_installed: '6.11.0' },
      },
    },
  },
}

function handleNodeSelect(node: SelectedNodeDetail | null) {
  selectedNode.value = node
  isPanelOpen.value = node !== null
}

function handlePanelClose() {
  selectedNode.value = null
  isPanelOpen.value = false
}

const { initializeTree, zoomIn, zoomOut, resetZoom } = useD3Tree({
  svgRef,
  onNodeSelect: handleNodeSelect,
})

onMounted(() => {
  initializeTree(sampleData)
})
</script>

<template>
  <div class="flex-1 flex w-full">
    <div class="grow relative overflow-hidden bg-white border border-slate-200">
      <header class="absolute top-0 left-0 p-6 z-10 pointer-events-none">
        <h1 class="text-xl font-bold text-slate-900 pointer-events-auto uppercase tracking-tight">
          Transitive Dependencies
        </h1>
        <p class="text-sm text-slate-500 pointer-events-auto">
          Root positioned left. Click nodes for details or to toggle visibility.
        </p>
      </header>

      <div class="absolute bottom-4 right-4 z-10 flex flex-col gap-1">
        <button
          class="w-8 h-8 flex items-center justify-center bg-white border border-slate-300 rounded shadow-sm hover:bg-slate-50 text-slate-700 text-lg font-bold leading-none"
          title="Zoom in"
          @click="zoomIn"
        >
          +
        </button>
        <button
          class="w-8 h-8 flex items-center justify-center bg-white border border-slate-300 rounded shadow-sm hover:bg-slate-50 text-slate-700 text-lg font-bold leading-none"
          title="Zoom out"
          @click="zoomOut"
        >
          &minus;
        </button>
        <button
          class="w-8 h-8 flex items-center justify-center bg-white border border-slate-300 rounded shadow-sm hover:bg-slate-50 text-slate-700 text-xs leading-none"
          title="Reset zoom"
          @click="resetZoom"
        >
          1:1
        </button>
      </div>

      <svg ref="svgRef" class="w-full h-full"></svg>
    </div>

    <DependencyDetailPanel :node="selectedNode" :is-open="isPanelOpen" @close="handlePanelClose" />
  </div>
</template>

<style scoped>
:deep(.node) {
  cursor: pointer;
}

:deep(.node circle) {
  stroke-width: 2.5px;
  transition: all 0.2s;
}

:deep(.node:hover circle) {
  r: 8px;
  filter: brightness(1.1);
}

:deep(.node text) {
  font: 12px sans-serif;
  transition: opacity 0.2s;
}

:deep(.node-label) {
  font-size: 12px;
  font-weight: bold;
  fill: #1e293b;
}

:deep(.version-label) {
  font-size: 10px;
  fill: #64748b;
  font-weight: normal;
}

:deep(.link) {
  fill: none;
  stroke: #cbd5e1;
  stroke-width: 1.5px;
  opacity: 0.6;
  transition: all 0.3s;
}

:deep(.link-duplicate) {
  fill: none;
  stroke: #94a3b8;
  stroke-width: 2px;
  stroke-dasharray: 5, 5;
  opacity: 0.5;
  transition: opacity 0.3s;
}

:deep(.link-duplicate:hover) {
  opacity: 1;
  stroke: #3b82f6;
}

:deep(.collapsed circle) {
  fill-opacity: 0.5 !important;
  stroke-width: 4px !important;
}
</style>
