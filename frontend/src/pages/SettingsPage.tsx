import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { useResource } from '../hooks/useResource.ts'
import { getSettings } from '../services/api.ts'

export function SettingsPage() {
  const state = useResource(
    getSettings,
    'settings',
    'The settings request failed.',
  )
  const data = state.data

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="Settings"
        description="Read-only. Editing comes later; values are defined in backend config."
      />
      {state.loading ? (
        <LoadingState label="Loading settings" lines={4} />
      ) : null}
      {state.error ? (
        <ErrorState message={state.error} onRetry={state.reload} />
      ) : null}
      {!state.loading && !state.error && !data ? (
        <EmptyState title="No settings yet" />
      ) : null}
      {data ? (
        <div className="grid gap-3">
          <section className="rounded-card border border-border bg-surface p-4 text-sm">
            <h2 className="font-medium text-text">Connection</h2>
            <dl className="mt-2 grid gap-2">
              <div>
                <dt className="text-xs text-text-muted">Data mode</dt>
                <dd>{data.dataMode}</dd>
              </div>
              <div>
                <dt className="text-xs text-text-muted">API URL</dt>
                <dd>{data.apiUrl || 'Not used in demo mode'}</dd>
              </div>
              <div>
                <dt className="text-xs text-text-muted">Wazuh version</dt>
                <dd>{data.wazuhVersion}</dd>
              </div>
            </dl>
          </section>
          <section className="rounded-card border border-border bg-surface p-4">
            <h2 className="text-sm font-medium text-text">Risk weights</h2>
            <table className="mt-2 w-full text-left text-sm">
              <thead className="text-xs text-text-muted">
                <tr>
                  <th className="py-1 font-medium">Event</th>
                  <th className="py-1 text-right font-medium">Points</th>
                </tr>
              </thead>
              <tbody>
                {data.weights.map((row) => (
                  <tr key={row.label} className="border-t border-border">
                    <td className="py-1">{row.label}</td>
                    <td className="py-1 text-right">{row.points}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section className="rounded-card border border-border bg-surface p-4">
            <h2 className="text-sm font-medium text-text">Asset multipliers</h2>
            <table className="mt-2 w-full text-left text-sm">
              <thead className="text-xs text-text-muted">
                <tr>
                  <th className="py-1 font-medium">Asset</th>
                  <th className="py-1 text-right font-medium">Multiplier</th>
                </tr>
              </thead>
              <tbody>
                {data.multipliers.map((row) => (
                  <tr key={row.assetType} className="border-t border-border">
                    <td className="py-1">
                      {row.assetType.replaceAll('_', ' ')}
                    </td>
                    <td className="py-1 text-right">{row.multiplier}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section className="rounded-card border border-border bg-surface p-4">
            <h2 className="text-sm font-medium text-text">Severity bands</h2>
            <ul className="mt-2 space-y-2">
              {data.bands.map((band) => (
                <li key={band.severity} className="flex items-center gap-2">
                  <SeverityBadge severity={band.severity} />
                  <span className="text-sm text-text-muted">{band.rule}</span>
                </li>
              ))}
            </ul>
          </section>
        </div>
      ) : null}
    </div>
  )
}
