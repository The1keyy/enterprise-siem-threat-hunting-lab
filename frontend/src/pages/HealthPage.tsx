import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useResource } from '../hooks/useResource.ts'
import { getCorrelationStatus, getHealth } from '../services/api.ts'

function dash(value: string | number | null): string {
  if (value === null || value === '') return '—'
  return String(value)
}

export function HealthPage() {
  const state = useResource(getHealth, 'health', 'The health request failed.')
  const correlation = useResource(
    getCorrelationStatus,
    'correlation',
    'The correlation status request failed.',
  )
  const data = state.data

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="System Health"
        description="Version 4.14.9 is the pinned target. Nothing here was checked against a running manager."
      />
      <section className="mb-3 rounded-card border border-border bg-surface p-4">
        <h2 className="text-sm font-medium text-text">Correlation</h2>
        {correlation.loading ? (
          <LoadingState label="Loading correlation status" lines={2} />
        ) : null}
        {correlation.error ? (
          <ErrorState message={correlation.error} onRetry={correlation.reload} />
        ) : null}
        {correlation.data ? (
          <dl className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs text-text-muted">Poller</dt>
              <dd>{correlation.data.enabled ? 'On' : 'Off'}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-muted">Last run</dt>
              <dd>{dash(correlation.data.lastRun)}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-muted">Checkpoint</dt>
              <dd>
                {correlation.data.checkpoint
                  ? `${correlation.data.checkpoint.timestamp} ${correlation.data.checkpoint.id}`
                  : '—'}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-text-muted">Alerts processed</dt>
              <dd>{correlation.data.alertsProcessed}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-xs text-text-muted">Note</dt>
              <dd>{correlation.data.note}</dd>
            </div>
            {correlation.data.error ? (
              <div className="sm:col-span-2">
                <dt className="text-xs text-text-muted">Error</dt>
                <dd className="text-high">{correlation.data.error}</dd>
              </div>
            ) : null}
          </dl>
        ) : null}
      </section>
      {state.loading ? <LoadingState label="Loading health" lines={4} /> : null}
      {state.error ? (
        <ErrorState message={state.error} onRetry={state.reload} />
      ) : null}
      {!state.loading && !state.error && !data ? (
        <EmptyState title="No health data yet" />
      ) : null}
      {data ? (
        <div className="grid gap-3">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {data.components.map((item) => (
              <article
                key={item.id}
                className="rounded-card border border-border bg-surface p-4"
              >
                <h2 className="text-sm font-medium text-text">{item.name}</h2>
                <div className="mt-2">
                  <StatusPill kind="health" status={item.status} />
                </div>
                <p className="mt-2 text-sm text-text-muted">
                  Version {item.version}
                </p>
                <p className="text-sm text-text-muted">
                  Last check {dash(item.lastCheck)}
                </p>
              </article>
            ))}
          </div>
          <section className="rounded-card border border-border bg-surface p-4">
            <h2 className="text-sm font-medium text-text">
              Event pipeline (agent → manager → indexer)
            </h2>
            <ol className="mt-3 flex flex-wrap items-center gap-2">
              {data.pipeline.map((step, index) => (
                <li key={step} className="flex items-center gap-2">
                  <span className="rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text">
                    {step}
                  </span>
                  {index < data.pipeline.length - 1 ? (
                    <span aria-hidden="true" className="text-text-muted">
                      →
                    </span>
                  ) : null}
                </li>
              ))}
            </ol>
          </section>
          <section className="grid gap-3 md:grid-cols-3">
            <article className="rounded-card border border-border bg-surface p-4">
              <h2 className="text-sm font-medium text-text">
                Indexer disk usage
              </h2>
              <div
                className="mt-3 h-2 rounded-full bg-surface-2"
                aria-hidden="true"
              >
                <div
                  className="h-full rounded-full bg-accent"
                  style={{
                    width:
                      data.diskPercent === null ? '0%' : `${data.diskPercent}%`,
                  }}
                />
              </div>
              <p className="mt-2 text-sm text-text">
                {data.diskPercent === null ? '—' : `${data.diskPercent}%`}
              </p>
              <p className="text-xs text-text-muted">Not measured.</p>
            </article>
            <article className="rounded-card border border-border bg-surface p-4">
              <h2 className="text-sm font-medium text-text">
                Failed ingestion
              </h2>
              <p className="mt-2 text-sm text-text">
                {dash(data.failedIngestion)}
              </p>
            </article>
            <article className="rounded-card border border-border bg-surface p-4">
              <h2 className="text-sm font-medium text-text">Active rules</h2>
              <p className="mt-2 text-sm text-text">{data.activeRules}</p>
              <p className="text-xs text-text-muted">
                Enabled rows in the detection library.
              </p>
            </article>
          </section>
          <section className="overflow-x-auto rounded-card border border-border bg-surface">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-2 text-xs text-text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">IP</th>
                  <th className="px-3 py-2 font-medium">OS</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Version</th>
                  <th className="px-3 py-2 font-medium">Last keep-alive</th>
                  <th className="px-3 py-2 font-medium">Last telemetry</th>
                </tr>
              </thead>
              <tbody>
                {data.agents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-3">
                      <EmptyState title="No agents yet" />
                    </td>
                  </tr>
                ) : (
                  data.agents.map((agent) => (
                    <tr key={agent.name} className="border-t border-border">
                      <td className="px-3 py-2">{agent.name}</td>
                      <td className="px-3 py-2">{agent.ip}</td>
                      <td className="px-3 py-2">{agent.os}</td>
                      <td className="px-3 py-2">{agent.status}</td>
                      <td className="px-3 py-2">{dash(agent.version)}</td>
                      <td className="px-3 py-2">{dash(agent.lastKeepAlive)}</td>
                      <td className="px-3 py-2">{dash(agent.lastTelemetry)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </section>
        </div>
      ) : null}
    </div>
  )
}
