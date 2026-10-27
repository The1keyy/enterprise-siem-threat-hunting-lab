import { useNavigate, useSearchParams } from 'react-router'
import { DataTable, type DataTableColumn } from '../components/DataTable.tsx'
import { HostLink, UserLink } from '../components/EntityLink.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { useResource } from '../hooks/useResource.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { listEntityHosts, listEntityUsers } from '../services/api.ts'
import type { EntityRow } from '../types/entity.ts'

function columns(
  tab: 'users' | 'hosts',
): readonly DataTableColumn<EntityRow>[] {
  return [
    {
      id: 'name',
      header: 'Name',
      accessor: (row) => row.name,
      cell: (row) =>
        tab === 'users' ? (
          <UserLink name={row.name} />
        ) : (
          <HostLink name={row.name} />
        ),
    },
    { id: 'risk', header: 'Risk score', accessor: (row) => row.riskScore },
    {
      id: 'incidents',
      header: 'Related incidents',
      accessor: (row) => row.incidentIds.length,
    },
    {
      id: 'last',
      header: 'Last activity',
      accessor: (row) => row.lastActivity ?? '',
      cell: (row) => (row.lastActivity ? formatLabTime(row.lastActivity) : '—'),
    },
  ]
}

export function EntitiesPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'hosts' ? 'hosts' : 'users'
  const users = useResource(
    listEntityUsers,
    'users',
    'The entities request failed.',
  )
  const hosts = useResource(
    listEntityHosts,
    'hosts',
    'The entities request failed.',
  )
  const active = tab === 'hosts' ? hosts : users
  const rows = active.data ?? []

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="Entities"
        description="Risk scores are decayed incident subtotals. The half-life is 24 hours, and the asset multiplier is not applied again."
      />
      <div className="mb-4 flex gap-2">
        {(['users', 'hosts'] as const).map((item) => (
          <button
            key={item}
            type="button"
            aria-pressed={tab === item}
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
            onClick={() => setParams(item === 'users' ? {} : { tab: item })}
          >
            {item === 'users' ? 'Users' : 'Hosts'}
          </button>
        ))}
      </div>
      {active.loading ? (
        <LoadingState label="Loading entities" lines={5} />
      ) : null}
      {active.error ? (
        <ErrorState message={active.error} onRetry={active.reload} />
      ) : null}
      {!active.loading && !active.error && rows.length === 0 ? (
        <EmptyState title="No entities yet" />
      ) : null}
      {!active.loading && !active.error && rows.length > 0 ? (
        <DataTable
          columns={columns(tab)}
          rows={rows}
          getRowId={(row) => row.name}
          initialSort={{ id: 'risk', direction: 'desc' }}
          onRowActivate={(row) =>
            navigate(
              tab === 'users'
                ? `/entities/users/${encodeURIComponent(row.name)}`
                : `/entities/hosts/${encodeURIComponent(row.name)}`,
            )
          }
        />
      ) : null}
    </div>
  )
}
