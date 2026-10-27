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
    path: '/incidents/INC-0001',
    body: 'This incident is a hand-written demo fixture. The correlation engine is real and tested, and it does not fill this queue yet.',
  },
  {
    title: 'Timeline',
    path: '/incidents/INC-0001',
    hash: 'timeline',
    body: 'The stages follow the attack story in the fixture. A chip means a user, source IP, or host also appears on an earlier event.',
  },
  {
    title: 'Risk breakdown',
    path: '/incidents/INC-0001',
    hash: 'risk',
    body: 'The score is rule-based. Each row is a category and its points. A row with zero points is not counted and stays muted.',
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
