export const DEMO_SAVE_TOAST = 'Demo mode: changes are not saved'

type ToastListener = (message: string) => void

const listeners = new Set<ToastListener>()

export function pushToast(message: string): void {
  for (const listener of listeners) {
    listener(message)
  }
}

export function subscribeToasts(listener: ToastListener): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}
