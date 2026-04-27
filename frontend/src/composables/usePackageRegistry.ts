import { shallowRef, watch, markRaw, computed } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import { buildPackageRegistry } from '@/explorer/registry'
import type { PackageRegistry } from '@/types/registry'

export function usePackageRegistry() {
  const store = useOssiqStore()
  const registry = shallowRef<PackageRegistry | null>(null)

  watch(
    () => store.report,
    (report) => {
      registry.value = report ? markRaw(buildPackageRegistry(report)) : null
    },
    { immediate: true },
  )

  const projectName = computed(() => store.report?.project.name ?? '')

  return { registry, projectName }
}
