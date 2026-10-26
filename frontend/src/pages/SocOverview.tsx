import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { BarList } from '../charts/BarList.tsx'
import { SeverityDonut } from '../charts/SeverityDonut.tsx'
import { TimeSeriesChart } from '../charts/TimeSeriesChart.tsx'
import { severityColor, severityLabel } from '../charts/chartTheme.ts'
import { Card } from '../components/Card.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { KpiCard } from '../components/KpiCard.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { HostLink, UserLink } from '../components/EntityLink.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useOverview } from '../hooks/useOverview.ts'
import type { OverviewData } from '../types/overview.ts'

const alertSeries = (['critical', 'high', 'medium', 'low'] as const).map(
  (severity) => ({
    key: severity,
    label: severityLabel[severity],
    color: severityColor[severity],
  }),
)

function formatLabTime(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

function Panel({
  title,
  className,
  loading,
  error,
  empty,
  onRetry,
  children,
}: {
  title: string
  className?: string
  loading: boolean
  error: string | null
  empty: boolean
  onRetry: () => void
  children: ReactNode
}) {
  return (
    <Card title={title} className={className}>
      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} onRetry={onRetry} />
      ) : empty ? (
        <EmptyState title="No data yet" />
      ) : (
        children
      )}
    </Card>
  )
}

export function SocOverview() {
  const { data, loading, error, reload } = useOverview()
  const criticalIncidents =
    data?.incidents.filter((incident) => incident.severity === 'critical') ?? []

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="SOC Overview"
        description="Figures on this page are demo fixtures."
        actions={
          <p className="text-xs text-text-muted">
            Last updated {data ? formatLabTime(data.generatedAt) : '—'}
          </p>
        }
      />

      <div className="flex flex-col gap-4">
        <KpiRow data={data} loading={loading} error={error} onRetry={reload} />

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-12">
          <Panel
            title="Alerts over time"
            className="min-w-0 xl:col-span-8"
            loading={loading}
            error={error}
            empty={!data || data.alertsOverTime.length === 0}
            onRetry={reload}
          >
            {data ? (
              <TimeSeriesChart
                data={data.alertsOverTime.map((bucket) => ({
                  label: bucket.label,
                  critical: bucket.critical,
                  high: bucket.high,
                  medium: bucket.medium,
                  low: bucket.low,
                }))}
                series={alertSeries}
                stacked
              />
            ) : null}
          </Panel>
          <Panel
            title="Alerts by severity"
            className="min-w-0 xl:col-span-4"
            loading={loading}
            error={error}
            empty={!data || data.alertsBySeverity.length === 0}
            onRetry={reload}
          >
            {data ? <SeverityDonut slices={data.alertsBySeverity} /> : null}
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-12">
          <Panel
            title="Alerts by MITRE tactic"
            className="min-w-0 xl:col-span-6"
            loading={loading}
            error={error}
            empty={!data || data.alertsByTactic.length === 0}
            onRetry={reload}
          >
            {data ? (
              <BarList
                labelWidth={156}
                items={data.alertsByTactic.map((item) => ({
                  label: item.tactic,
                  value: item.count,
                }))}
              />
            ) : null}
          </Panel>
          <Panel
            title="Authentication failures over time"
            className="min-w-0 xl:col-span-6"
            loading={loading}
            error={error}
            empty={!data || data.authFailuresOverTime.length === 0}
            onRetry={reload}
          >
            {data ? (
              <TimeSeriesChart
                data={data.authFailuresOverTime.map((bucket) => ({
                  label: bucket.label,
                  count: bucket.count,
                }))}
                series={[
                  {
                    key: 'count',
                    label: 'Authentication failures',
                    color: 'var(--color-medium)',
                  },
                ]}
                variant="line"
              />
            ) : null}
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-12">
          <Panel
            title="Top source IPs"
            className="min-w-0 xl:col-span-3"
            loading={loading}
            error={error}
            empty={!data || data.topSourceIps.length === 0}
            onRetry={reload}
          >
            {data ? (
              <BarList
                items={data.topSourceIps.map((item) => ({
                  label: item.label,
                  value: item.count,
                }))}
              />
            ) : null}
          </Panel>
          <Panel
            title="Top targeted users"
            className="min-w-0 xl:col-span-3"
            loading={loading}
            error={error}
            empty={!data || data.topTargetedUsers.length === 0}
            onRetry={reload}
          >
            {data ? (
              <BarList
                items={data.topTargetedUsers.map((item) => ({
                  label: item.label,
                  value: item.count,
                }))}
              />
            ) : null}
          </Panel>
          <Panel
            title="Top risky hosts"
            className="min-w-0 xl:col-span-3"
            loading={loading}
            error={error}
            empty={!data || data.topRiskyHosts.length === 0}
            onRetry={reload}
          >
            {data ? (
              <BarList
                color="var(--color-high)"
                items={data.topRiskyHosts.map((item) => ({
                  label: item.name,
                  value: item.riskScore,
                }))}
              />
            ) : null}
          </Panel>
          <Panel
            title="Top risky users"
            className="min-w-0 xl:col-span-3"
            loading={loading}
            error={error}
            empty={!data || data.topRiskyUsers.length === 0}
            onRetry={reload}
          >
            {data ? (
              <BarList
                color="var(--color-high)"
                items={data.topRiskyUsers.map((item) => ({
                  label: item.name,
                  value: item.riskScore,
                }))}
              />
            ) : null}
          </Panel>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-12">
          <Panel
            title="Latest critical incidents"
            className="min-w-0 xl:col-span-4"
            loading={loading}
            error={error}
            empty={Boolean(data) && criticalIncidents.length === 0}
            onRetry={reload}
          >
            <ul className="flex flex-col gap-2">
              {criticalIncidents.map((incident) => (
                <li
                  key={incident.id}
                  className="rounded-md px-2 py-2 hover:bg-surface-2"
                >
                  <Link
                    to={`/incidents/${incident.id}`}
                    className="block text-sm font-medium text-text"
                  >
                    {incident.id} · {incident.title}
                  </Link>
                  <span className="mt-2 flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={incident.severity} />
                    <StatusPill kind="incident" status={incident.status} />
                  </span>
                  <span className="mt-1 block text-xs text-text-muted">
                    <HostLink name={incident.host} /> ·{' '}
                    <UserLink name={incident.user} /> ·{' '}
                    {formatLabTime(incident.lastSeen)}
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel
            title="Recent detections"
            className="min-w-0 xl:col-span-4"
            loading={loading}
            error={error}
            empty={!data || data.recentDetections.length === 0}
            onRetry={reload}
          >
            {data ? (
              <ul className="flex flex-col gap-3">
                {data.recentDetections.map((detection) => (
                  <li
                    key={`${detection.id}-${detection.time}`}
                    className="flex flex-col gap-1 border-b border-border pb-2 last:border-b-0"
                  >
                    <span className="text-sm text-text">
                      {detection.id} · {detection.name}
                    </span>
                    <span className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={detection.severity} />
                      <span className="text-xs text-text-muted">
                        <HostLink name={detection.host} /> ·{' '}
                        {formatLabTime(detection.time)}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            ) : null}
          </Panel>
          <Panel
            title="Active ATT&CK techniques"
            className="min-w-0 xl:col-span-4"
            loading={loading}
            error={error}
            empty={!data || data.activeTechniques.length === 0}
            onRetry={reload}
          >
            {data ? (
              <ul className="flex flex-wrap gap-2">
                {data.activeTechniques.map((technique) => (
                  <li key={technique.id}>
                    <span className="inline-flex items-center gap-2 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-text">
                      <span className="font-medium text-accent">
                        {technique.id}
                      </span>
                      {technique.name}
                    </span>
                  </li>
                ))}
              </ul>
            ) : null}
          </Panel>
        </section>

        <Panel
          title="Pipeline health"
          className="min-w-0"
          loading={loading}
          error={error}
          empty={!data || data.health.length === 0}
          onRetry={reload}
        >
          {data ? (
            <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {data.health.map((item) => (
                <li
                  key={item.name}
                  className="flex flex-col gap-2 rounded-md border border-border bg-surface-2 p-3"
                >
                  <span className="text-sm text-text">{item.name}</span>
                  <StatusPill kind="health" status={item.status} />
                  <span className="text-xs text-text-muted">
                    Last event {formatLabTime(item.lastEvent)}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
        </Panel>
      </div>
    </div>
  )
}

function KpiRow({
  data,
  loading,
  error,
  onRetry,
}: {
  data: OverviewData | null
  loading: boolean
  error: string | null
  onRetry: () => void
}) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-12">
        {Array.from({ length: 7 }, (_, index) => (
          <Card
            key={index}
            className={
              index < 4 ? 'min-w-0 xl:col-span-3' : 'min-w-0 xl:col-span-4'
            }
          >
            <LoadingState lines={2} />
          </Card>
        ))}
      </div>
    )
  }

  if (error || !data) {
    return (
      <ErrorState
        message={error ?? 'The overview request failed.'}
        onRetry={onRetry}
      />
    )
  }

  const cards: { label: string; value: number | null; hint?: string }[] = [
    { label: 'Active Incidents', value: data.kpis.activeIncidents },
    { label: 'Critical Alerts (24h)', value: data.kpis.criticalAlerts24h },
    { label: 'High Alerts (24h)', value: data.kpis.highAlerts24h },
    { label: 'Monitored Endpoints', value: data.kpis.monitoredEndpoints },
    {
      label: 'Detection Rules Enabled',
      value: data.kpis.detectionRulesEnabled,
    },
    { label: 'Events Ingested (24h)', value: data.kpis.eventsIngested24h },
    {
      label: 'Mean Time to Investigate',
      value: data.kpis.meanTimeToInvestigateMinutes,
      hint:
        data.kpis.meanTimeToInvestigateMinutes === null
          ? 'Not enough data yet'
          : undefined,
    },
  ]

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-12">
      {cards.map((card, index) => (
        <div
          key={card.label}
          className={
            index < 4 ? 'min-w-0 xl:col-span-3' : 'min-w-0 xl:col-span-4'
          }
        >
          <KpiCard label={card.label} value={card.value} hint={card.hint} />
        </div>
      ))}
    </div>
  )
}
