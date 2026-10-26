import { detectionFixtures } from '../fixtures/detections.ts'
import { huntFixtures } from '../fixtures/hunts.ts'
import { incidentFixtures } from '../fixtures/incidents.ts'
import { aggregateLowCounts, eventMatchesQuery } from '../lib/huntQuery.ts'
import type { Detection } from '../types/detection.ts'
import type {
  Hunt,
  HuntFilters,
  HuntHit,
  HuntRunResult,
} from '../types/hunt.ts'
import { ApiError } from './apiError.ts'
import { DEMO_SAVE_TOAST, pushToast } from './toasts.ts'

let detections: Detection[] | null = null

function detectionStore(): Detection[] {
  if (!detections) {
    detections = structuredClone(detectionFixtures) as Detection[]
  }
  return detections
}

export function resetDemoCatalog(): void {
  detections = null
}

export function listDemoDetections(): Detection[] {
  return detectionStore()
}

export function getDemoDetection(id: string): Detection {
  const found = detectionStore().find((item) => item.id === id)
  if (!found) {
    throw new ApiError(`Detection ${id} was not found.`, 404)
  }
  return found
}

export function setDemoDetectionEnabled(
  id: string,
  enabled: boolean,
): Detection {
  const index = detectionStore().findIndex((item) => item.id === id)
  const current = detectionStore()[index]
  if (!current) {
    throw new ApiError(`Detection ${id} was not found.`, 404)
  }
  const next = { ...current, enabled }
  detectionStore()[index] = next
  pushToast(DEMO_SAVE_TOAST)
  return next
}

export const HUNT_NOTICE =
  'Demo results — matched fixture timeline events. Not a wazuh-archives-* result.'

export function listDemoHunts(): Hunt[] {
  return huntFixtures.map((hunt) => ({ ...hunt }))
}

export function huntCorpus(): HuntHit[] {
  return incidentFixtures.flatMap((incident) =>
    incident.timeline.map((event) => ({ ...event, incidentId: incident.id })),
  )
}

export function runDemoHunt(
  id: string,
  filters: HuntFilters,
  query: string,
): HuntRunResult {
  const hunt = huntFixtures.find((item) => item.id === id)
  if (!hunt) {
    throw new ApiError(`Hunt ${id} was not found.`, 404)
  }
  let hits = huntCorpus().filter((event) => {
    if (!eventMatchesQuery(query, event)) return false
    if (filters.host && event.host !== filters.host) return false
    if (filters.user && event.user !== filters.user) return false
    if (filters.source && event.source !== filters.source) return false
    const eventMs = Date.parse(event.time)
    if (filters.from && eventMs < Date.parse(filters.from)) return false
    if (filters.to && eventMs > Date.parse(filters.to)) return false
    return true
  })
  const grouped = hunt.aggregation
    ? aggregateLowCounts(hits, hunt.aggregation)
    : null
  if (grouped) hits = grouped.hits
  return {
    demo: true,
    notice: HUNT_NOTICE,
    huntId: id,
    hits,
    buckets: grouped?.buckets ?? [],
  }
}
