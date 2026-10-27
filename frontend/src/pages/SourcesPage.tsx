import { TimeSeriesChart } from '../charts/TimeSeriesChart.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { WindowsValidationTag } from '../components/WindowsValidationTag.tsx'
import { useResource } from '../hooks/useResource.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { listSources } from '../services/api.ts'

export function SourcesPage() {
  const state = useResource(
    listSources,
    'sources',
    'The data sources request failed.',
  )

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="Data Sources"
        description="Volume bars count fixture timeline events. They are not ingested telemetry."
      />
      <p className="mb-4 rounded-card border border-border bg-surface px-4 py-3 text-sm text-text">
        Real status appears after the lab is connected.
      </p>
      {state.loading ? (
        <LoadingState label="Loading data sources" lines={4} />
      ) : null}
      {state.error ? (
        <ErrorState message={state.error} onRetry={state.reload} />
      ) : null}
      {!state.loading && !state.error && (state.data?.length ?? 0) === 0 ? (
        <EmptyState title="No data sources yet" />
      ) : null}
      {!state.loading && !state.error && state.data ? (
        <div className="grid gap-3 lg:grid-cols-2">
          {state.data.map((source) => (
            <article
              key={source.id}
              className="rounded-card border border-border bg-surface p-4"
            >
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-medium text-text">{source.name}</h2>
                <StatusPill kind="health" status={source.status} />
                {source.optional ? (
                  <span className="rounded-md border border-border px-1.5 py-0.5 text-xs text-text-muted">
                    Optional / not deployed
                  </span>
                ) : null}
                {source.windowsValidationRequired ? (
                  <WindowsValidationTag />
                ) : null}
              </div>
              <dl className="mt-3 grid gap-2 text-sm">
                <div>
                  <dt className="text-xs text-text-muted">Hosts</dt>
                  <dd>
                    {source.hosts.length === 0 ? '—' : source.hosts.join(', ')}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">Agent</dt>
                  <dd>{source.agent}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">
                    Last event received
                  </dt>
                  <dd>
                    {source.lastEvent ? formatLabTime(source.lastEvent) : '—'}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">Ingestion errors</dt>
                  <dd>
                    {source.ingestionErrors === null
                      ? '—'
                      : source.ingestionErrors}
                  </dd>
                </div>
              </dl>
              <h3 className="mt-3 text-xs text-text-muted">
                Event volume (24h)
              </h3>
              <TimeSeriesChart
                variant="line"
                data={source.volume}
                series={[
                  {
                    key: 'count',
                    label: 'Fixture events',
                    color: 'var(--color-accent)',
                  },
                ]}
              />
            </article>
          ))}
        </div>
      ) : null}
    </div>
  )
}
