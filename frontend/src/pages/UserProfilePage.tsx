import { useCallback } from 'react'
import { Link, useParams } from 'react-router'
import { TimeSeriesChart } from '../charts/TimeSeriesChart.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { HostLink } from '../components/EntityLink.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { RiskExplainer } from '../components/RiskExplainer.tsx'
import { useResource } from '../hooks/useResource.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { getUserProfile } from '../services/api.ts'
import type { UserProfile } from '../types/entity.ts'

function Profile({ data }: { data: UserProfile }) {
  return (
    <div className="min-w-0 overflow-x-hidden">
      <Link className="text-sm text-accent" to="/entities">
        Back to entities
      </Link>
      <header className="mt-3 mb-4">
        <p className="text-sm text-text-muted">User</p>
        <h1 className="text-xl font-semibold text-text">{data.name}</h1>
        <p className="mt-1 text-sm text-text-muted">
          Risk score {data.riskScore}. Decayed incident subtotal, 24-hour
          half-life. The asset multiplier is not applied again.
        </p>
      </header>
      <div className="grid gap-3">
        <section className="rounded-card border border-border bg-surface p-4">
          <h2 className="text-sm font-medium text-text">Recent logins</h2>
          {data.logins.length === 0 ? (
            <div className="mt-2">
              <EmptyState title="No logins in the fixture timeline" />
            </div>
          ) : (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-text-muted">
                  <tr>
                    <th className="py-1 font-medium">Time</th>
                    <th className="py-1 font-medium">Host</th>
                    <th className="py-1 font-medium">Source IP</th>
                    <th className="py-1 font-medium">Logon type</th>
                    <th className="py-1 font-medium">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {data.logins.map((row) => (
                    <tr
                      key={`${row.time}-${row.host}-${row.result}`}
                      className="border-t border-border"
                    >
                      <td className="py-1">{formatLabTime(row.time)}</td>
                      <td className="py-1">
                        <HostLink name={row.host} />
                      </td>
                      <td className="py-1">{row.sourceIp}</td>
                      <td className="py-1">{row.logonType}</td>
                      <td className="py-1">{row.result}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="rounded-card border border-border bg-surface p-4 text-sm">
          <h2 className="font-medium text-text">Source IPs</h2>
          <p className="mt-1 text-text-muted">
            {data.sourceIps.length === 0 ? '—' : data.sourceIps.join(', ')}
          </p>
          <h2 className="mt-3 font-medium text-text">Associated endpoints</h2>
          <p className="mt-1">
            {data.endpoints.length === 0
              ? '—'
              : data.endpoints.map((host) => (
                  <span key={host} className="mr-2">
                    <HostLink name={host} />
                  </span>
                ))}
          </p>
          <h2 className="mt-3 font-medium text-text">Triggered detections</h2>
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
          <h2 className="mt-3 font-medium text-text">Related incidents</h2>
          <ul className="mt-1 space-y-1">
            {data.incidents.map((item) => (
              <li key={item.id}>
                <Link className="text-accent" to={`/incidents/${item.id}`}>
                  {item.id} {item.name}
                </Link>
              </li>
            ))}
          </ul>
          <h2 className="mt-3 font-medium text-text">MITRE activity</h2>
          <ul className="mt-2 flex flex-wrap gap-1">
            {data.mitre.map((item) => (
              <li
                key={item.id}
                className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-accent"
              >
                {item.id} {item.name}
              </li>
            ))}
          </ul>
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

export function UserProfilePage() {
  const { name = '' } = useParams()
  const decoded = decodeURIComponent(name)
  const load = useCallback(() => getUserProfile(decoded), [decoded])
  const state = useResource(load, decoded, 'The user request failed.')
  if (!decoded) return <EmptyState title="User not found" />
  if (state.loading) return <LoadingState label="Loading user" lines={5} />
  if (state.notFound) return <EmptyState title="User not found" />
  if (state.error || !state.data) {
    return (
      <ErrorState
        message={state.error ?? 'The user request failed.'}
        onRetry={state.reload}
      />
    )
  }
  return <Profile data={state.data} />
}
