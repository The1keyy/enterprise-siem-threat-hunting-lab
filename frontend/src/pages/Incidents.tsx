import { useMemo } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { DataTable, type DataTableColumn } from '../components/DataTable.tsx'
import { HostLink, UserLink } from '../components/EntityLink.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { IncidentFilterBar } from '../components/incidents/IncidentFilterBar.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useIncidents } from '../hooks/useIncidents.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import {
  EMPTY_FILTERS,
  filtersFromSearch,
  searchFromFilters,
} from '../lib/incidentFilters.ts'
import type { Incident, MitreTechnique } from '../types/incident.ts'

function MitreChips({ items }: { items: readonly MitreTechnique[] }) {
  const shown = items.slice(0, 2)
  const extra = items.length - shown.length
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((item) => (
        <span
          key={item.id}
          className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-accent"
        >
          {item.id}
        </span>
      ))}
      {extra > 0 ? (
        <span className="text-xs text-text-muted">+{extra}</span>
      ) : null}
    </span>
  )
}

const RISK_BAR: Record<Incident['severity'], string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
  info: 'bg-accent',
}

function RiskCell({
  score,
  severity,
}: {
  score: number
  severity: Incident['severity']
}) {
  const width = Math.min(100, Math.round((score / 150) * 100))
  return (
    <span className="inline-flex items-center gap-2">
      <span className="w-8 tabular-nums">{score}</span>
      <span
        className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-2"
        aria-hidden="true"
      >
        <span
          className={`block h-full ${RISK_BAR[severity]}`}
          style={{ width: `${width}%` }}
        />
      </span>
    </span>
  )
}

const COLUMNS: readonly DataTableColumn<Incident>[] = [
  {
    id: 'id',
    header: 'ID',
    accessor: (row) => row.id,
    cellClassName: 'whitespace-nowrap font-mono text-xs',
  },
  { id: 'title', header: 'Title', accessor: (row) => row.title },
  {
    id: 'severity',
    header: 'Severity',
    accessor: (row) => row.severity,
    cell: (row) => <SeverityBadge severity={row.severity} />,
  },
  {
    id: 'riskScore',
    header: 'Risk',
    accessor: (row) => row.riskScore,
    cell: (row) => (
      <RiskCell score={row.riskScore} severity={row.severity} />
    ),
  },
  {
    id: 'status',
    header: 'Status',
    accessor: (row) => row.status,
    cell: (row) => <StatusPill kind="incident" status={row.status} />,
  },
  {
    id: 'user',
    header: 'User',
    accessor: (row) => row.users[0] ?? '',
    cellClassName: 'whitespace-nowrap font-mono text-xs',
    cell: (row) => (
      <span className="flex flex-col gap-1">
        {row.users.map((name) => (
          <UserLink key={name} name={name} />
        ))}
      </span>
    ),
  },
  {
    id: 'host',
    header: 'Host',
    accessor: (row) => row.hosts[0] ?? '',
    cellClassName: 'whitespace-nowrap font-mono text-xs',
    cell: (row) => (
      <span className="flex flex-col gap-1">
        {row.hosts.map((name) => (
          <HostLink key={name} name={name} />
        ))}
      </span>
    ),
  },
  {
    id: 'mitre',
    header: 'MITRE',
    accessor: (row) => row.mitre.map((item) => item.id).join(' '),
    cell: (row) => <MitreChips items={row.mitre} />,
  },
  {
    id: 'firstSeen',
    header: 'First seen',
    accessor: (row) => row.firstSeen,
    cell: (row) => formatLabTime(row.firstSeen),
  },
  {
    id: 'lastSeen',
    header: 'Last seen',
    accessor: (row) => row.lastSeen,
    cell: (row) => formatLabTime(row.lastSeen),
  },
  { id: 'owner', header: 'Owner', accessor: (row) => row.owner },
]

export function Incidents() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => filtersFromSearch(params), [params])
  const { data, loading, error, reload } = useIncidents(filters)
  const critical =
    data?.filter((row) => row.severity === 'critical').length ?? 0

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="Incidents"
        description="Figures on this page are demo fixtures."
      />
      <div className="mb-4">
        <IncidentFilterBar
          filters={filters}
          onChange={(next) => setParams(searchFromFilters(next))}
          onClear={() => setParams(searchFromFilters(EMPTY_FILTERS))}
        />
      </div>
      {loading ? (
        <LoadingState label="Loading incidents" layout="table" lines={6} />
      ) : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {!loading && !error && data ? (
        <>
          <p className="mb-3 text-sm tabular-nums text-text-muted">
            {data.length} {data.length === 1 ? 'incident' : 'incidents'} ·{' '}
            {critical} critical
          </p>
          {data.length === 0 ? (
            <EmptyState title="No incidents match these filters" />
          ) : (
            <DataTable
              columns={COLUMNS}
              rows={data}
              getRowId={(row) => row.id}
              initialSort={{ id: 'riskScore', direction: 'desc' }}
              emptyTitle="No incidents match these filters"
              onRowActivate={(row) => navigate(`/incidents/${row.id}`)}
            />
          )}
        </>
      ) : null}
    </div>
  )
}
