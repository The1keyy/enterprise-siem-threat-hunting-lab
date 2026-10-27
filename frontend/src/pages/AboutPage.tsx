import { ArchitectureDiagram } from '../components/ArchitectureDiagram.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useDetections } from '../hooks/useDetections.ts'
import { VALIDATION_STATUSES } from '../types/domain.ts'

const REPO = 'https://github.com/The1keyy/enterprise-siem-threat-hunting-lab'

export function AboutPage() {
  const { data, loading, error, reload } = useDetections()
  const counts = VALIDATION_STATUSES.map((status) => ({
    status,
    count: data?.filter((item) => item.status === status).length ?? 0,
  }))

  return (
    <div className="min-w-0">
      <PageHeader
        title="About SentinelForge"
        description="A free SOC lab on Wazuh, with an analyst console on top. The Mac build is complete. Lab validation has not started."
        actions={
          <a
            href={REPO}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-text transition-colors duration-150 hover:bg-surface-2"
          >
            GitHub
          </a>
        }
      />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <section className="min-w-0 rounded-card border border-border bg-surface p-4 xl:col-span-7">
          <h2 className="text-lg font-medium text-text">What this is</h2>
          <p className="mt-2 text-sm text-text-muted">
            SentinelForge does not replace Wazuh. The console reads alerts,
            keeps incidents, and scores them with rules you can read. Detections
            in the library are the rules in this repository. Incident rows in
            demo mode are fixtures, not a live correlation run.
          </p>
          <h2 className="mt-6 text-lg font-medium text-text">Architecture</h2>
          <div className="mt-3 overflow-hidden rounded-md border border-border">
            <ArchitectureDiagram />
          </div>
        </section>
        <section className="min-w-0 rounded-card border border-border bg-surface p-4 xl:col-span-5">
          <h2 className="text-lg font-medium text-text">Validation</h2>
          <p className="mt-2 text-sm text-text-muted">
            Counts come from the detection metadata loaded in this console.
          </p>
          {loading ? <LoadingState label="Loading detection counts" /> : null}
          {error ? <ErrorState message={error} onRetry={reload} /> : null}
          {!loading && !error && data && data.length === 0 ? (
            <EmptyState title="No detections yet" />
          ) : null}
          {!loading && !error && data && data.length > 0 ? (
            <ul className="mt-4 flex flex-col gap-3">
              {counts.map((item) => (
                <li
                  key={item.status}
                  className="flex items-center justify-between gap-3"
                >
                  <StatusPill kind="validation" status={item.status} />
                  <span className="text-sm tabular-nums text-text">
                    {item.count}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
        </section>
      </div>
    </div>
  )
}
