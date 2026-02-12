import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import type { OSSIQExportSchemaV10 } from '@/types/report'

export const useOssiqStore = defineStore('ossiq', () => {
  const report = ref<OSSIQExportSchemaV10 | null>(null)

  const isLoaded = computed(() => report.value !== null)
  const projectName = computed(() => report.value?.project.name ?? null)
  const productionPackages = computed(() => report.value?.production_packages ?? [])
  const developmentPackages = computed(() => report.value?.development_packages ?? [])

  function setReport(data: OSSIQExportSchemaV10) {
    report.value = data
  }

  return { report, isLoaded, projectName, productionPackages, developmentPackages, setReport }
})
