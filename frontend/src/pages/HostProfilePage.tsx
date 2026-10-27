import { useCallback } from 'react'
import { Link, useParams } from 'react-router'
import { TimeSeriesChart } from '../charts/TimeSeriesChart.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { UserLink } from '../components/EntityLink.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { RiskExplainer } from '../components/RiskExplainer.tsx'
import { useResource } from '../hooks/useResource.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { getHostProfile } from '../services/api.ts'
import type { HostProfile } from '../types/entity.ts'

function assetLabel(asset: HostProfile['assetType']): string {
  if (asset === 'domain_controller') return 'domain controller'
  return asset
}

function Profile({ data }: { data: HostProfile }) {
  return (
    <div className="min-w-0 overflow-x-hidden">
      <Link className="text-sm text-accent" to="/entities?tab=hosts">
        Back to entities
      </Link>
      <header className="mt-3 mb-4">
        <p className="text-sm text-text-muted">Host</p>
        <h1 className="text-xl font-semibold text-text">{data.name}</h1>
        <p className="mt-1 text-sm text-text-muted">
          {data.ip} · {data.os}
        </p>
        <p className="mt-1 text-sm text-text">
          Asset criticality {assetLabel(data.assetType)} × {data.multiplier}
        </p>
        <p className="mt-1 text-sm text-text-muted">
          Agent status {data.agentStatus} · Risk score {data.riskScore}. Decayed
          incident subtotal, 24-hour half-life. The asset multiplier is not
          applied again.
        </p>
      </header>
      <div className="grid gap-3">
        <section className="rounded-card border border-border bg-surface p-4 text-sm">
          <h2 className="font-medium text-text">Users</h2>
          <p className="mt-1">
            {data.users.length === 0
              ? '—'
              : data.users.map((user) => (
                  <span key={user} className="mr-2">
                    <UserLink name={user} />
                  </span>
                ))}
          </p>
          <h2 className="mt-3 font-medium text-text">Top processes</h2>
          {data.processes.length === 0 ? (
            <p className="mt-1 text-text-muted">No data yet.</p>
          ) : (
            <ul className="mt-1">
              {data.processes.map((item) => (
                <li key={item.name}>
                  {item.name} · {item.count}
                </li>
              ))}
            </ul>
          )}
          <h2 className="mt-3 font-medium text-text">Detections</h2>
          <ul className="mt-1 space-y-1">
            {data.detections.length === 0 ? (
              <li className="text-text-muted">No data yet.</li>
            ) : (
              data.detections.map((item) => (
                <li key={item.id}>
                  <Link className="text-accent" to={`/detections/${item.id}`}>
                    {item.id} {item.name}
                  </Link>
                </li>
              ))
            )}
          </ul>
          <h2 className="mt-3 font-medium text-text">Incidents</h2>
          <ul className="mt-1 space-y-1">
            {data.incidents.map((item) => (
              <li key={item.id}>
                <Link className="text-accent" to={`/incidents/${item.id}`}>
                  {item.id} {item.name}
                </Link>
              </li>
            ))}
          </ul>
        </section>
        <section className="rounded-card border border-border bg-surface p-4">
          <h2 className="text-sm font-medium text-text">Network connections</h2>
          {data.connections.length === 0 ? (
            <div className="mt-2">
              <EmptyState title="No connections in the fixture timeline" />
            </div>
          ) : (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-text-muted">
                  <tr>
                    <th className="py-1 font-medium">Time</th>
                    <th className="py-1 font-medium">Source</th>
                    <th className="py-1 font-medium">Destination</th>
                    <th className="py-1 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {data.connections.map((row) => (
                    <tr
                      key={`${row.time}-${row.src}-${row.detail}`}
                      className="border-t border-border"
                    >
                      <td className="py-1">{formatLabTime(row.time)}</td>
                      <td className="py-1">{row.src}</td>
                      <td className="py-1">{row.dst}</td>
                      <td className="py-1">{row.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="rounded-card border border-border bg-surface p-4">
          <h2 className="mb-2 text-sm font-medium text-text">
            Risk history (7 days)
          </h2>
          <TimeSeriesChart
            variant="line"
            data={data.history}
            series={[
              {
                key: 'score',
                label: 'Risk score',
                color: 'var(--color-accent)',
              },
            ]}
          />
        </section>
        <RiskExplainer lines={data.lines} />
      </div>
    </div>
  )
}

export function HostProfilePage() {
  const { name = '' } = useParams()
  const decoded = decodeURIComponent(name)
  const load = useCallback(() => getHostProfile(decoded), [decoded])
  const state = useResource(load, decoded, 'The host request failed.')
  if (!decoded) return <EmptyState title="Host not found" />
  if (state.loading) return <LoadingState label="Loading host" lines={5} />
  if (state.notFound) return <EmptyState title="Host not found" />
  if (state.error || !state.data) {
    return (
      <ErrorState
        message={state.error ?? 'The host request failed.'}
        onRetry={state.reload}
      />
    )
  }
  return <Profile data={state.data} />
}
