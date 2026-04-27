import { ref, computed } from 'vue'
import type { NavFrame } from '@/types/registry'

export function useNavigationStack() {
  // Empty = at project root. Each entry is one level of navigation.
  const stack = ref<NavFrame[]>([])

  const current = computed<NavFrame | null>(() => stack.value.at(-1) ?? null)
  const canGoBack = computed<boolean>(() => stack.value.length > 0)

  function push(frame: NavFrame): void {
    stack.value = [...stack.value, frame]
  }

  function pop(): void {
    stack.value = stack.value.slice(0, -1)
  }

  /** Keep frames [0..index] inclusive; equivalent to clicking a breadcrumb ancestor. */
  function jumpTo(index: number): void {
    if (index >= 0 && index < stack.value.length) {
      stack.value = stack.value.slice(0, index + 1)
    }
  }

  function reset(): void {
    stack.value = []
  }

  return { stack, current, canGoBack, push, pop, jumpTo, reset }
}
