import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import type { OSSIQExportSchemaV14 } from '@/types/report'

export const useOssiqStore = defineStore('ossiq', () => {
  const report = ref<OSSIQExportSchemaV14 | null>(null)

  const isLoaded = computed(() => report.value !== null)
  const projectName = computed(() => report.value?.project.name ?? null)
  const productionPackages = computed(() => report.value?.production_packages ?? [])
  const developmentPackages = computed(() => report.value?.development_packages ?? [])
  const transitivePackages = computed(() => report.value?.transitive_packages ?? [])

  function setReport(data: OSSIQExportSchemaV14) {
    report.value = data
  }

  return { report, isLoaded, projectName, productionPackages, developmentPackages, transitivePackages, setReport }
})
