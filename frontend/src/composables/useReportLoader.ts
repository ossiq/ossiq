import { onMounted, onUnmounted } from 'vue'
import { useOssiqStore } from '@/stores/ossiq'
import type { OSSIQExportSchemaV10 } from '@/types/report'

const SCRIPT_TYPE = 'json/oss-iq-report'

function parseReportScript(el: HTMLScriptElement): OSSIQExportSchemaV10 | null {
  const text = el.textContent?.trim()
  if (!text) return null
  try {
    return JSON.parse(text) as OSSIQExportSchemaV10
  } catch {
    return null
  }
}

function findReportScripts(): NodeListOf<HTMLScriptElement> {
  return document.querySelectorAll<HTMLScriptElement>(`script[type="${SCRIPT_TYPE}"]`)
}

export function useReportLoader() {
  const store = useOssiqStore()
  let observer: MutationObserver | null = null

  function scanExistingScripts() {
    for (const el of findReportScripts()) {
      const data = parseReportScript(el)
      if (data) {
        store.setReport(data)
        return
      }
    }
  }

  function handleMutations(mutations: MutationRecord[]) {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node instanceof HTMLScriptElement && node.type === SCRIPT_TYPE) {
          const data = parseReportScript(node)
          if (data) {
            store.setReport(data)
            return
          }
        }
      }
    }
  }

  onMounted(() => {
    scanExistingScripts()

    observer = new MutationObserver(handleMutations)
    observer.observe(document, { childList: true, subtree: true })
  })

  onUnmounted(() => {
    observer?.disconnect()
    observer = null
  })

  return { isLoaded: store.isLoaded }
}
