import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { WindowsValidationTag } from '../components/WindowsValidationTag.tsx'
import { useDetection } from '../hooks/useDetections.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import type { Detection } from '../types/detection.ts'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-card border border-border bg-surface p-4">
      <h2 className="text-sm font-medium text-text">{title}</h2>
      <div className="mt-2 text-sm text-text-muted">{children}</div>
    </section>
  )
}

function CodeBlock({ text }: { text: string }) {
  return (
    <pre className="mt-2 overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-xs text-text">
      {text}
    </pre>
  )
}

function DetailBody({ data }: { data: Detection }) {
  return (
    <div className="min-w-0 overflow-x-hidden">
      <Link className="text-sm text-accent" to="/detections">
        Back to detections
      </Link>
      <header className="mt-3 mb-4">
        <p className="text-sm text-text-muted">{data.id}</p>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-text">{data.name}</h1>
          <SeverityBadge severity={data.severity} />
          <StatusPill kind="validation" status={data.status} />
          {data.windowsValidationRequired ? <WindowsValidationTag /> : null}
        </div>
        <p className="mt-2 text-sm text-text-muted">
          Version {data.version}
          {' · '}
          {data.enabled ? 'Enabled' : 'Disabled'}
          {' · '}
          Last triggered{' '}
          {data.lastTriggered ? formatLabTime(data.lastTriggered) : '—'}
          {' · '}
          Alerts {data.alertCount === null ? '—' : data.alertCount}
        </p>
      </header>
      <div className="grid gap-3">
        <Section title="Objective">
          <p>{data.description}</p>
        </Section>
        <Section title="Logic">
          <p>
            {`Look for ${data.expectedEvent}${
              data.telemetry.length > 0
                ? ` on ${data.telemetry.join(', ')}`
                : ''
            }.`}
            {data.wazuhRuleXml.startsWith('Not written yet')
              ? ' The rule text is not written yet (Step 10).'
              : null}
          </p>
        </Section>
        <Section title="Event Requirements">
          <p>{data.expectedEvent}</p>
          <p className="mt-1">Telemetry: {data.telemetry.join(', ')}</p>
        </Section>
        <Section title="MITRE">
          <ul className="space-y-1">
            {data.mitre.map((item) => (
              <li key={item.id}>
                <span className="text-accent">{item.id}</span> {item.name}
                <span className="text-text-muted"> · {item.tactic}</span>
              </li>
            ))}
          </ul>
        </Section>
        <Section title="Wazuh Rule">
          <CodeBlock text={data.wazuhRuleXml} />
        </Section>
        <Section title="Sigma Rule">
          <CodeBlock text={data.sigmaYaml} />
        </Section>
        <Section title="False Positives">
          <p>{data.falsePositives}</p>
        </Section>
        <Section title="Test Procedure">
          <p>{data.testProcedure}</p>
        </Section>
        <Section title="Expected Event">
          <p>{data.expectedEvent}</p>
        </Section>
        <Section title="Expected Alert">
          <p>{data.expectedAlert}</p>
        </Section>
        <Section title="Observed Result">
          <p>{data.observedResult}</p>
        </Section>
        <Section title="Tuning History">
          {data.tuningHistory.length === 0 ? (
            <EmptyState title="No tuning yet" detail="No data yet." />
          ) : (
            <ul className="space-y-2">
              {data.tuningHistory.map((change) => (
                <li key={`${change.time}-${change.author}`}>
                  {formatLabTime(change.time)} · {change.author}: {change.note}
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </div>
  )
}

export function DetectionDetail() {
  const { id = '' } = useParams()
  const { data, loading, error, notFound, reload } = useDetection(id)

  if (!id) {
    return <EmptyState title="Detection not found" />
  }
  if (loading) {
    return <LoadingState label="Loading detection" lines={6} />
  }
  if (notFound) {
    return <EmptyState title="Detection not found" />
  }
  if (error || !data) {
    return (
      <ErrorState
        message={error ?? 'The detection request failed.'}
        onRetry={reload}
      />
    )
  }
  return <DetailBody data={data} />
}
