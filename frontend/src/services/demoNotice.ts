import { useSyncExternalStore } from 'react'

let sawDemo = false
const listeners = new Set<() => void>()

export function noteDemo(value: boolean): void {
  if (!value || sawDemo) return
  sawDemo = true
  for (const listener of listeners) listener()
}

export function useDemoNotice(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    () => sawDemo,
    () => false,
  )
}
