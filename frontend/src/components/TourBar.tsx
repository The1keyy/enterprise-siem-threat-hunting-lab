import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { readTourStep, TOUR_STEPS, writeTourStep } from '../lib/tour.ts'

export function TourBar() {
  const navigate = useNavigate()
  const location = useLocation()
  const [index, setIndex] = useState<number | null>(() => readTourStep())

  useEffect(() => {
    const sync = () => setIndex(readTourStep())
    window.addEventListener('sf-tour', sync)
    return () => window.removeEventListener('sf-tour', sync)
  }, [])

  const step = index === null ? null : TOUR_STEPS[index]

  useEffect(() => {
    if (!step) return
    if (location.pathname !== step.path) {
      navigate({ pathname: step.path, hash: step.hash ? `#${step.hash}` : '' })
      return
    }
    if (!step.hash) return
    document.getElementById(step.hash)?.scrollIntoView({ block: 'start' })
  }, [location.pathname, navigate, step])

  if (index === null || !step) return null

  function go(next: number | null) {
    writeTourStep(next)
  }

  return (
    <div className="fixed inset-x-0 bottom-0 z-30 border-t border-border bg-surface px-4 py-3 sm:px-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="text-xs text-text-muted">
            Tour {index + 1} of {TOUR_STEPS.length} · {step.title}
          </p>
          <p className="mt-1 max-w-3xl text-sm text-text">{step.body}</p>
        </div>
        <div className="flex shrink-0 gap-2">
          <button
            type="button"
            className="rounded-md border border-border px-3 py-1.5 text-sm text-text transition-colors duration-150 hover:bg-surface-2"
            onClick={() => go(null)}
          >
            Exit
          </button>
          <button
            type="button"
            className="rounded-md border border-border px-3 py-1.5 text-sm text-text transition-colors duration-150 hover:bg-surface-2 disabled:opacity-40"
            disabled={index === 0}
            onClick={() => go(index - 1)}
          >
            Back
          </button>
          <button
            type="button"
            className="rounded-md border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-text transition-colors duration-150 hover:bg-accent/25"
            onClick={() => go(index === TOUR_STEPS.length - 1 ? null : index + 1)}
          >
            {index === TOUR_STEPS.length - 1 ? 'Done' : 'Next'}
          </button>
        </div>
      </div>
    </div>
  )
}
