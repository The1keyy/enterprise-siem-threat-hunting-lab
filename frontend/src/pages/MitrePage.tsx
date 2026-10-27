import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { clsx } from 'clsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useDetections } from '../hooks/useDetections.ts'
import {
  attackNavigatorLayer,
  bestValidationStatus,
  coverageSummary,
} from '../lib/coverage.ts'
import { TACTIC_COLUMNS, techniquesForTactic } from '../lib/techniques.ts'
import { VALIDATION_STATUSES, type ValidationStatus } from '../types/domain.ts'
import type { Detection } from '../types/detection.ts'
import type { MitreTechnique } from '../types/incident.ts'

const TILE_FILL: Record<ValidationStatus, string> = {
  'NOT TESTED': 'border-border bg-surface-2 text-text-muted',
  'SYNTAX VALID': 'border-low/40 bg-low/20 text-text',
  'LOGTEST VALID': 'border-accent/40 bg-accent/15 text-text',
  'LAB VALIDATED': 'border-ok/40 bg-ok/20 text-text',
  'NEEDS TUNING': 'border-medium/40 bg-medium/20 text-text',
}

function alertsGenerated(detections: readonly Detection[]): string {
  if (detections.some((item) => item.alertCount === null)) return '—'
  return String(
    detections.reduce((sum, item) => sum + (item.alertCount ?? 0), 0),
  )
}

function downloadLayer(detections: readonly Detection[]) {
  const layer = attackNavigatorLayer(detections)
  const blob = new Blob([JSON.stringify(layer, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'sentinelforge-attack-layer.json'
  anchor.click()
  URL.revokeObjectURL(url)
}

export function MitrePage() {
  const { data, loading, error, reload } = useDetections()
  const [openId, setOpenId] = useState<string | null>(null)

  const summary = useMemo(
    () => (data ? coverageSummary(data) : { mapped: 0, labValidated: 0 }),
    [data],
  )

  const open = useMemo(() => {
    if (!data || !openId) return null
    const technique = data
      .flatMap((item) => item.mitre)
      .find((item) => item.id === openId)
    if (!technique) return null
    const mapped = data.filter((item) =>
      item.mitre.some((entry) => entry.id === openId),
    )
    return { technique, mapped }
  }, [data, openId])

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="MITRE ATT&CK"
        description={
          data
            ? `${summary.mapped} techniques mapped · ${summary.labValidated} lab validated`
            : 'Coverage is computed from the detection library.'
        }
        actions={
          <button
            type="button"
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
            disabled={!data}
            onClick={() => {
              if (data) downloadLayer(data)
            }}
          >
            Export ATT&CK Navigator layer
          </button>
        }
      />
      <ul className="mb-4 flex flex-wrap items-center gap-2">
        {VALIDATION_STATUSES.map((status) => (
          <li key={status}>
            <StatusPill kind="validation" status={status} />
          </li>
        ))}
        <li>
          <span className="inline-flex items-center rounded-full border border-dashed border-border px-2 py-0.5 text-xs text-text-muted">
            Not covered
          </span>
        </li>
      </ul>
      {loading ? (
        <LoadingState label="Loading ATT&CK coverage" lines={6} />
      ) : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {!loading && !error && data && data.length === 0 ? (
        <EmptyState title="No detections yet" />
      ) : null}
      {!loading && !error && data && data.length > 0 ? (
        <div>
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-5 xl:grid-cols-10">
            {TACTIC_COLUMNS.map((tactic) => {
              const techniques = techniquesForTactic(tactic)
              return (
                <section key={tactic} aria-label={tactic} className="min-w-0">
                  <h2 className="mb-2 text-xs font-medium leading-snug text-text">
                    {tactic}
                  </h2>
                  {techniques.length === 0 ? (
                    <p className="rounded-md border border-dashed border-border bg-bg px-2 py-3 text-xs text-text-muted">
                      Not covered
                    </p>
                  ) : (
                    <ul className="space-y-2">
                      {techniques.map((technique) => (
                        <li key={technique.id}>
                          <TechniqueTile
                            technique={technique}
                            detections={data}
                            onOpen={() => setOpenId(technique.id)}
                          />
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              )
            })}
          </div>
        </div>
      ) : null}
      {open ? (
        <div className="fixed inset-0 z-40 flex justify-end bg-bg/70">
          <aside
            role="dialog"
            aria-label={`${open.technique.id} ${open.technique.name}`}
            className="h-full w-full max-w-md overflow-y-auto border-l border-border bg-surface p-4"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm text-accent">{open.technique.id}</p>
                <h2 className="text-lg font-semibold text-text">
                  {open.technique.name}
                </h2>
                <p className="text-sm text-text-muted">
                  {open.technique.tactic}
                </p>
              </div>
              <button
                type="button"
                className="rounded-md border border-border px-2 py-1 text-sm text-text"
                onClick={() => setOpenId(null)}
              >
                Close
              </button>
            </div>
            <dl className="mt-4 space-y-3 text-sm">
              <div>
                <dt className="text-text-muted">Mapped detections</dt>
                <dd className="mt-1">
                  <ul className="space-y-1">
                    {open.mapped.map((detection) => (
                      <li key={detection.id}>
                        <Link
                          className="text-accent"
                          to={`/detections/${detection.id}`}
                        >
                          {detection.id} {detection.name}
                        </Link>
                      </li>
                    ))}
                  </ul>
                </dd>
              </div>
              <div>
                <dt className="text-text-muted">Alerts generated</dt>
                <dd className="text-text">{alertsGenerated(open.mapped)}</dd>
              </div>
              <div>
                <dt className="text-text-muted">Validation status</dt>
                <dd className="mt-1">
                  <StatusPill
                    kind="validation"
                    status={bestValidationStatus(
                      open.mapped.map((item) => item.status),
                    )}
                  />
                </dd>
              </div>
              <div>
                <dt className="text-text-muted">Simulations performed</dt>
                <dd className="text-text">None yet</dd>
              </div>
            </dl>
          </aside>
        </div>
      ) : null}
    </div>
  )
}

function TechniqueTile({
  technique,
  detections,
  onOpen,
}: {
  technique: MitreTechnique
  detections: readonly Detection[]
  onOpen: () => void
}) {
  const mapped = detections.filter((item) =>
    item.mitre.some((entry) => entry.id === technique.id),
  )
  if (mapped.length === 0) return null
  const status = bestValidationStatus(mapped.map((item) => item.status))
  return (
    <button
      type="button"
      className={clsx(
        'w-full rounded-md border p-2 text-left transition-colors duration-150',
        TILE_FILL[status],
      )}
      onClick={onOpen}
    >
      <p className="font-mono text-xs">{technique.id}</p>
      <p className="mt-1 text-xs leading-snug text-text">{technique.name}</p>
      <p className="mt-2 text-xs font-medium">{status}</p>
    </button>
  )
}
