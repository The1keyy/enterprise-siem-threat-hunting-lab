import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { Card } from '../components/Card.tsx'
import { HostLink, UserLink } from '../components/EntityLink.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { EvidencePanel } from '../components/incidents/EvidencePanel.tsx'
import { ResponseActions } from '../components/incidents/ResponseActions.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useIncident } from '../hooks/useIncident.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { groupingChips } from '../lib/grouping.ts'
import {
  DISPOSITIONS,
  INCIDENT_OWNERS,
  type IncidentDetail as IncidentDetailData,
  type RiskAssetType,
} from '../types/incident.ts'
import { INCIDENT_STATUSES } from '../types/domain.ts'
import type { Severity } from '../types/domain.ts'

const fieldClass =
  'rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text'

const DOT: Record<Severity, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
  info: 'bg-accent',
}

function assetLabel(asset: RiskAssetType): string {
  if (asset === 'domain_controller') return 'domain controller'
  return asset
}

function EntityGroup({
  label,
  values,
  kind = 'plain',
}: {
  label: string
  values: readonly string[]
  kind?: 'user' | 'host' | 'plain'
}) {
  return (
    <div>
      <h3 className="text-xs font-medium text-text-muted">{label}</h3>
      {values.length === 0 ? (
        <p className="mt-1 text-sm text-text-muted">No data yet</p>
      ) : (
        <ul className="mt-1 flex flex-wrap gap-1">
          {values.map((value) => (
            <li
              key={value}
              className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-text"
            >
              {kind === 'user' ? <UserLink name={value} /> : null}
              {kind === 'host' ? <HostLink name={value} /> : null}
              {kind === 'plain' ? (
                <span className="font-mono">{value}</span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Workspace({ id }: { id: string }) {
  const {
    data,
    loading,
    error,
    notFound,
    reload,
    setStatus,
    setOwner,
    addAnalystNote,
    saveAnalystFields,
    confirmDryRun,
  } = useIncident(id)
  const [selected, setSelected] = useState(0)
  const [note, setNote] = useState('')

  if (loading) return <LoadingState label="Loading incident" lines={8} />
  if (notFound) {
    return (
      <>
        <Link className="text-sm text-accent" to="/incidents">
          Back to incidents
        </Link>
        <div className="mt-4">
          <EmptyState title="Incident not found" />
        </div>
      </>
    )
  }
  if (error && !data) return <ErrorState message={error} onRetry={reload} />
  if (!data) return <EmptyState title="No data yet" />

  return (
    <IncidentBody
      data={data}
      selected={selected}
      note={note}
      error={error}
      onSelect={setSelected}
      onNote={setNote}
      onStatus={(status) => void setStatus(status)}
      onOwner={(owner) => void setOwner(owner)}
      onAddNote={() => {
        const text = note.trim()
        if (!text) return
        void addAnalystNote(text).then(() => setNote(''))
      }}
      onDisposition={(disposition) => void saveAnalystFields({ disposition })}
      onSummary={(summary) => {
        if (summary !== data.summary) void saveAnalystFields({ summary })
      }}
      onDryRun={confirmDryRun}
    />
  )
}

type BodyProps = {
  data: IncidentDetailData
  selected: number
  note: string
  error: string | null
  onSelect: (index: number) => void
  onNote: (value: string) => void
  onStatus: (status: IncidentDetailData['status']) => void
  onOwner: (owner: string) => void
  onAddNote: () => void
  onDisposition: (disposition: IncidentDetailData['disposition']) => void
  onSummary: (summary: string) => void
  onDryRun: (
    action: 'Isolate lab endpoint' | 'Disable test account' | 'Block test IP',
    target: string,
  ) => Promise<void>
}

function IncidentBody({
  data,
  selected,
  note,
  error,
  onSelect,
  onNote,
  onStatus,
  onOwner,
  onAddNote,
  onDisposition,
  onSummary,
  onDryRun,
}: BodyProps) {
  const event = data.timeline[selected] ?? data.timeline[0] ?? null
  const ruleIds = [...new Set(data.timeline.map((item) => item.ruleId))]
  const multiplier = data.risk.multiplier.toFixed(1)
  const chips = groupingChips(data.timeline)

  return (
    <div className="min-w-0 overflow-x-hidden">
      <Link className="text-sm text-accent" to="/incidents">
        Back to incidents
      </Link>
      <header className="mt-3 mb-4">
        <p className="font-mono text-sm text-text-muted">{data.id}</p>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-text">{data.title}</h1>
          <SeverityBadge severity={data.severity} />
          <span className="text-sm text-text">Risk {data.riskScore}</span>
        </div>
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs text-text-muted">
            Status
            <span className="flex items-center gap-2">
              <StatusPill kind="incident" status={data.status} />
              <select
                aria-label="Status"
                className={fieldClass}
                value={data.status}
                onChange={(change) =>
                  onStatus(change.target.value as IncidentDetailData['status'])
                }
              >
                {INCIDENT_STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {status}
                  </option>
                ))}
              </select>
            </span>
          </label>
          <label className="flex flex-col gap-1 text-xs text-text-muted">
            Owner
            <select
              aria-label="Owner"
              className={fieldClass}
              value={data.owner}
              onChange={(change) => onOwner(change.target.value)}
            >
              {INCIDENT_OWNERS.map((owner) => (
                <option key={owner} value={owner}>
                  {owner}
                </option>
              ))}
            </select>
          </label>
          <p className="text-xs text-text-muted">
            First seen {formatLabTime(data.firstSeen)}
          </p>
          <p className="text-xs text-text-muted">
            Last seen {formatLabTime(data.lastSeen)}
          </p>
        </div>
        {error ? <p className="mt-2 text-sm text-critical">{error}</p> : null}
      </header>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-4 xl:col-span-7">
          <Card
            title="Timeline"
            subtitle="Why grouped is read from the user, source IP, or host already on these events."
          >
            {data.timeline.length === 0 ? (
              <EmptyState
                title="No events in this incident"
                detail="A timeline appears when the incident has events."
              />
            ) : (
              <ol id="timeline" className="relative space-y-0">
                {data.timeline.map((item, index) => {
                  const chip = chips[index]
                  return (
                    <li key={`${item.time}-${item.ruleId}`} className="relative pl-6">
                      {index < data.timeline.length - 1 ? (
                        <span
                          aria-hidden="true"
                          className="absolute top-3 bottom-0 left-[7px] w-px bg-border"
                        />
                      ) : null}
                      <span
                        aria-hidden="true"
                        className={`absolute top-2 left-0 h-4 w-4 rounded-full border-2 border-surface ${DOT[item.severity]}`}
                      />
                      <button
                        type="button"
                        className={
                          index === selected
                            ? 'mb-3 w-full rounded-md bg-surface-2 px-3 py-2 text-left transition-colors duration-150'
                            : 'mb-3 w-full rounded-md px-3 py-2 text-left transition-colors duration-150 hover:bg-surface-2'
                        }
                        aria-pressed={index === selected}
                        onClick={() => onSelect(index)}
                      >
                        <span className="flex flex-wrap items-center gap-2 text-xs text-text-muted">
                          {formatLabTime(item.time)}
                          <span className="capitalize text-text">
                            {item.severity}
                          </span>
                        </span>
                        <span className="mt-1 block text-sm text-text">
                          {item.title}
                        </span>
                        <span className="mt-1 block font-mono text-xs text-text-muted">
                          <HostLink name={item.host} /> ·{' '}
                          <UserLink name={item.user} /> · {item.ruleId}
                        </span>
                        {chip ? (
                          <span
                            className={
                              chip.strength === 'strong'
                                ? 'mt-2 inline-flex rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs text-text'
                                : 'mt-2 inline-flex rounded-full border border-border bg-surface px-2 py-0.5 text-xs text-text-muted'
                            }
                          >
                            {chip.strength === 'strong' ? 'Strong' : 'Weak'} ·{' '}
                            {chip.label}
                          </span>
                        ) : null}
                      </button>
                    </li>
                  )
                })}
              </ol>
            )}
          </Card>
          <Card title="Evidence">
            <EvidencePanel event={event} ruleIds={ruleIds} />
          </Card>
        </div>
        <div className="flex min-w-0 flex-col gap-4 xl:col-span-5">
          <Card title="Entities">
            <div className="space-y-3">
              <EntityGroup
                label="Users"
                values={data.entities.users}
                kind="user"
              />
              <EntityGroup
                label="Hosts"
                values={data.entities.hosts}
                kind="host"
              />
              <EntityGroup label="Source IPs" values={data.entities.srcIps} />
              <EntityGroup
                label="Destination IPs"
                values={data.entities.dstIps}
              />
              <EntityGroup label="Processes" values={data.entities.processes} />
              <EntityGroup label="Domains" values={data.entities.domains} />
              <EntityGroup label="Hashes" values={data.entities.hashes} />
            </div>
          </Card>
          <Card title="MITRE">
            <ul className="space-y-2">
              {data.mitre.map((item) => (
                <li key={item.id} className="text-sm text-text">
                  <span className="text-accent">{item.id}</span> {item.name}
                  <span className="mt-0.5 block text-xs text-text-muted">
                    {item.tactic}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
          <Card
            title="Risk score breakdown"
            subtitle="A row with zero points is not counted."
          >
            <table id="risk" className="w-full text-left text-sm">
              <thead className="text-xs text-text-muted">
                <tr>
                  <th className="py-1 font-medium">Event</th>
                  <th className="py-1 font-medium">Rule</th>
                  <th className="py-1 text-right font-medium">Points</th>
                </tr>
              </thead>
              <tbody>
                {data.risk.items.map((item) => {
                  const counted = item.points > 0
                  return (
                    <tr
                      key={`${item.ruleId}-${item.event}`}
                      className={
                        counted
                          ? 'border-t border-border'
                          : 'border-t border-border text-text-muted'
                      }
                    >
                      <td className="py-1.5 pr-2">
                        {item.event}
                        {counted ? null : (
                          <span className="mt-0.5 block text-xs">
                            Not counted
                          </span>
                        )}
                      </td>
                      <td className="py-1.5 font-mono text-xs">{item.ruleId}</td>
                      <td className="py-1.5 text-right tabular-nums">
                        {item.points}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            <p className="mt-3 text-sm text-text">
              {`Subtotal ${data.risk.subtotal} \u00d7 ${multiplier} (${assetLabel(data.risk.assetType)}) = ${data.risk.final}`}
            </p>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-sm text-text">Final {data.risk.final}</span>
              <SeverityBadge severity={data.risk.severityBand} />
            </div>
            <p className="mt-2 text-xs text-text-muted">
              Rule-based score, no ML
            </p>
          </Card>
          <Card title="Analyst">
            {data.notes.length === 0 ? (
              <p className="text-sm text-text-muted">No data yet</p>
            ) : (
              <ul className="space-y-2">
                {data.notes.map((item) => (
                  <li key={item.id} className="text-sm text-text">
                    <span className="text-xs text-text-muted">
                      {item.author} · {formatLabTime(item.time)}
                    </span>
                    <span className="mt-1 block">{item.text}</span>
                  </li>
                ))}
              </ul>
            )}
            <form
              className="mt-3"
              onSubmit={(submit) => {
                submit.preventDefault()
                onAddNote()
              }}
            >
              <label className="block text-xs text-text-muted" htmlFor="note">
                Add note
              </label>
              <textarea
                id="note"
                className={`${fieldClass} mt-1 min-h-16 w-full`}
                value={note}
                onChange={(change) => onNote(change.target.value)}
              />
              <button
                type="submit"
                className="mt-2 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
              >
                Add note
              </button>
            </form>
            <label className="mt-3 flex flex-col gap-1 text-xs text-text-muted">
              Disposition
              <select
                aria-label="Disposition"
                className={fieldClass}
                value={data.disposition}
                onChange={(change) =>
                  onDisposition(
                    change.target.value as IncidentDetailData['disposition'],
                  )
                }
              >
                {DISPOSITIONS.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
            </label>
            <label className="mt-3 flex flex-col gap-1 text-xs text-text-muted">
              Investigation summary
              <textarea
                className={`${fieldClass} min-h-20 w-full`}
                defaultValue={data.summary}
                key={data.summary}
                onBlur={(event) => onSummary(event.target.value)}
              />
            </label>
            <h3 className="mt-3 text-xs font-medium text-text-muted">
              Recommended containment
            </h3>
            <ul className="mt-1 list-disc space-y-1 pl-4 text-sm text-text">
              {data.recommendedContainment.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </Card>
          <Card title="Response actions">
            <ResponseActions
              audit={data.audit}
              onConfirm={onDryRun}
              actions={[
                {
                  name: 'Isolate lab endpoint',
                  target: data.hosts[0] ?? null,
                },
                {
                  name: 'Disable test account',
                  target: data.users[0] ?? null,
                },
                {
                  name: 'Block test IP',
                  target: data.entities.srcIps[0] ?? null,
                },
              ]}
            />
          </Card>
        </div>
      </div>
    </div>
  )
}

export function IncidentDetail() {
  const { id } = useParams()
  if (!id) return <EmptyState title="Incident not found" />
  return <Workspace key={id} id={id} />
}
