import { storyIncidentId } from '../fixtures/incidents.ts'

export type TourStep = {
  title: string
  path: string
  hash?: string
  body: string
}

export const TOUR_STEPS: readonly TourStep[] = [
  {
    title: 'Overview',
    path: '/',
    body: 'This overview is synthetic demo data. The counts are fixture arithmetic, not a live SOC.',
  },
  {
    title: 'Incident',
    path: `/incidents/${storyIncidentId}`,
    body: 'This incident was built by the correlation engine from synthetic alerts. The score is the risk model, not a lab result.',
  },
  {
    title: 'Timeline',
    path: `/incidents/${storyIncidentId}`,
    hash: 'timeline',
    body: 'The stages follow the synthetic attack story. A strong link shares a user or source IP. A weak link is the same host within 10 minutes when the event has no user.',
  },
  {
    title: 'Risk breakdown',
    path: `/incidents/${storyIncidentId}`,
    hash: 'risk',
    body: 'The score is rule-based. Each row is a category and its points. A row that is not counted stays visible with the reason.',
  },
  {
    title: 'Detection rule',
    path: '/detections/SF-002',
    body: 'This is a real detection rule from the repository. The sample cases are synthetic. The rule is not lab validated.',
  },
  {
    title: 'MITRE coverage',
    path: '/mitre',
    body: 'Each cell is a technique from the detection metadata. The shade is the validation status, and the status is written on the cell. None are lab validated.',
  },
]

const STORAGE_KEY = 'sf-tour-step'

export function readTourStep(): number | null {
  const raw = sessionStorage.getItem(STORAGE_KEY)
  if (raw === null) return null
  const index = Number(raw)
  if (!Number.isInteger(index) || index < 0 || index >= TOUR_STEPS.length) {
    return null
  }
  return index
}

export function writeTourStep(index: number | null) {
  if (index === null) sessionStorage.removeItem(STORAGE_KEY)
  else sessionStorage.setItem(STORAGE_KEY, String(index))
  window.dispatchEvent(new Event('sf-tour'))
}
