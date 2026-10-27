import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import { DataTable, type DataTableColumn } from '../components/DataTable.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useDetections } from '../hooks/useDetections.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { VALIDATION_STATUSES } from '../types/domain.ts'
import {
  TELEMETRY_SOURCES,
  type Detection,
  type DetectionSeverity,
  type TelemetrySource,
} from '../types/detection.ts'
import type { ValidationStatus } from '../types/domain.ts'

const SEVERITY_OPTIONS: DetectionSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
]

const fieldClass =
  'rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text'

function dash(value: string | null): string {
  return value ?? '—'
}

export function DetectionsPage() {
  const navigate = useNavigate()
  const { data, loading, error, reload, toggleEnabled } = useDetections()
  const [status, setStatus] = useState<ValidationStatus | ''>('')
  const [severity, setSeverity] = useState<DetectionSeverity | ''>('')
  const [telemetry, setTelemetry] = useState<TelemetrySource | ''>('')
  const [mitre, setMitre] = useState('')

  const techniques = useMemo(() => {
    const ids = new Set<string>()
    for (const item of data ?? []) {
      for (const technique of item.mitre) ids.add(technique.id)
    }
    return [...ids].sort()
  }, [data])

  const rows = useMemo(() => {
    return (data ?? []).filter((item) => {
      if (status && item.status !== status) return false
      if (severity && item.severity !== severity) return false
      if (telemetry && !item.telemetry.includes(telemetry)) return false
      if (mitre && !item.mitre.some((technique) => technique.id === mitre)) {
        return false
      }
      return true
    })
  }, [data, status, severity, telemetry, mitre])

  const counts = useMemo(() => {
    const tally = Object.fromEntries(
      VALIDATION_STATUSES.map((item) => [item, 0]),
    ) as Record<ValidationStatus, number>
    for (const item of rows) tally[item.status] += 1
    return tally
  }, [rows])

  const columns: readonly DataTableColumn<Detection>[] = [
    { id: 'id', header: 'ID', accessor: (row) => row.id },
    { id: 'name', header: 'Name', accessor: (row) => row.name },
    {
      id: 'severity',
      header: 'Severity',
      accessor: (row) => row.severity,
      cell: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      id: 'mitre',
      header: 'MITRE',
      accessor: (row) => row.mitre.map((item) => item.id).join(' '),
      cell: (row) => (
        <span className="text-xs text-accent">
          {row.mitre.map((item) => item.id).join(', ')}
        </span>
      ),
    },
    {
      id: 'telemetry',
      header: 'Telemetry',
      accessor: (row) => row.telemetry.join(', '),
    },
    {
      id: 'enabled',
      header: 'Enabled',
      accessor: (row) => (row.enabled ? 1 : 0),
      cell: (row) => (
        <input
          type="checkbox"
          aria-label={`Enabled ${row.id}`}
          checked={row.enabled}
          onClick={(event) => event.stopPropagation()}
          onChange={(event) => {
            event.stopPropagation()
            void toggleEnabled(row.id, event.target.checked)
          }}
        />
      ),
    },
    { id: 'version', header: 'Version', accessor: (row) => row.version },
    {
      id: 'lastTriggered',
      header: 'Last triggered',
      accessor: (row) => row.lastTriggered ?? '',
      cell: (row) =>
        row.lastTriggered ? formatLabTime(row.lastTriggered) : dash(null),
    },
    {
      id: 'alerts',
      header: 'Alerts',
      accessor: (row) => row.alertCount ?? -1,
      cell: (row) => (row.alertCount === null ? '—' : String(row.alertCount)),
    },
    {
      id: 'status',
      header: 'Status',
      accessor: (row) => row.status,
      cell: (row) => <StatusPill kind="validation" status={row.status} />,
    },
  ]

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="Detections"
        description="Rules from this repository. Windows rules are not lab validated. Library figures are demo fixtures."
      />
      <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label className="flex flex-col gap-1 text-xs text-text-muted">
          Status
          <select
            className={fieldClass}
            value={status}
            onChange={(event) =>
              setStatus(event.target.value as ValidationStatus | '')
            }
          >
            <option value="">Any status</option>
            {VALIDATION_STATUSES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-text-muted">
          Severity
          <select
            className={fieldClass}
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value as DetectionSeverity | '')
            }
          >
            <option value="">Any severity</option>
            {SEVERITY_OPTIONS.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-text-muted">
          Telemetry
          <select
            className={fieldClass}
            value={telemetry}
            onChange={(event) =>
              setTelemetry(event.target.value as TelemetrySource | '')
            }
          >
            <option value="">Any telemetry</option>
            {TELEMETRY_SOURCES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-text-muted">
          MITRE
          <select
            className={fieldClass}
            value={mitre}
            onChange={(event) => setMitre(event.target.value)}
          >
            <option value="">Any technique</option>
            {techniques.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
      </div>
      {loading ? <LoadingState label="Loading detections" lines={6} /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {!loading && !error && data ? (
        <>
          <ul className="mb-3 flex flex-wrap gap-2">
            {VALIDATION_STATUSES.map((item) => (
              <li key={item}>
                <StatusPill kind="validation" status={item} />
                <span className="ml-1 text-sm text-text-muted">
                  {counts[item]}
                </span>
              </li>
            ))}
          </ul>
          {rows.length === 0 ? (
            <EmptyState title="No detections match these filters" />
          ) : (
            <DataTable
              columns={columns}
              rows={rows}
              getRowId={(row) => row.id}
              initialSort={{ id: 'id', direction: 'asc' }}
              emptyTitle="No detections match these filters"
              onRowActivate={(row) => navigate(`/detections/${row.id}`)}
            />
          )}
        </>
      ) : null}
    </div>
  )
}
