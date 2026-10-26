import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { TimeSeriesChart } from '../charts/TimeSeriesChart.tsx'
import { HostLink, UserLink } from '../components/EntityLink.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { promoteHits, useHuntRun, useHunts } from '../hooks/useHunts.ts'
import { formatLabTime } from '../lib/formatLabTime.ts'
import { LAB_HOSTS } from '../lib/incidentFilters.ts'
import type { Severity } from '../types/domain.ts'
import type { Hunt, HuntHit } from '../types/hunt.ts'
import { INCIDENT_OWNERS } from '../types/incident.ts'

/** Same instant as the overview fixture. Demo hunts do not use the wall clock. */
const DEMO_NOW = Date.parse('2026-10-25T16:00:00Z')

const LAB_USERS = [
  'sf-test-alice',
  'sf-test-bob',
  'sf-test-carol',
  'sf-test-dave',
] as const

const EVENT_SOURCES = [
  'windows_security',
  'sysmon',
  'powershell',
  'linux_auth',
  'auditd',
] as const

const RANGES = {
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
} as const

type RangeKey = keyof typeof RANGES

const SEVERITY_OPTIONS: Severity[] = ['critical', 'high', 'medium', 'low']

const fieldClass =
  'rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text'

function hitKey(hit: HuntHit, index: number): string {
  return `${hit.incidentId}|${hit.time}|${hit.ruleId}|${index}`
}

export function HuntingPage() {
  const navigate = useNavigate()
  const hunts = useHunts()
  const run = useHuntRun()
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [queryOverride, setQueryOverride] = useState<string | null>(null)
  const [titleOverride, setTitleOverride] = useState<string | null>(null)
  const [range, setRange] = useState<RangeKey>('24h')
  const [host, setHost] = useState('')
  const [user, setUser] = useState('')
  const [source, setSource] = useState('')
  const [selectedHits, setSelectedHits] = useState<string[]>([])
  const [openRaw, setOpenRaw] = useState<string | null>(null)
  const [promoteOpen, setPromoteOpen] = useState(false)
  const [severity, setSeverity] = useState<Severity>('medium')
  const [owner, setOwner] = useState<string>(INCIDENT_OWNERS[0])
  const [promoteError, setPromoteError] = useState<string | null>(null)

  const visibleHunts = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return (hunts.data ?? []).filter((hunt) =>
      needle.length === 0 ? true : hunt.name.toLowerCase().includes(needle),
    )
  }, [hunts.data, search])

  const selected =
    hunts.data?.find((hunt) => hunt.id === selectedId) ??
    hunts.data?.[0] ??
    null
  const query = queryOverride ?? selected?.query ?? ''
  const title = titleOverride ?? selected?.name ?? ''
  const hits = useMemo(() => run.result?.hits ?? [], [run.result])

  const chart = useMemo(() => {
    const buckets = new Map<string, number>()
    for (const hit of hits) {
      const label = hit.time.slice(11, 16)
      buckets.set(label, (buckets.get(label) ?? 0) + 1)
    }
    return [...buckets.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([label, events]) => ({ label, events }))
  }, [hits])

  function choose(hunt: Hunt) {
    setSelectedId(hunt.id)
    setQueryOverride(hunt.query)
    setTitleOverride(hunt.name)
    setRange(hunt.timeWindowDefault)
    setSelectedHits([])
    setOpenRaw(null)
  }

  function applyPivot(field: string) {
    let clause = `${field}:`
    if (field === 'agent.name' && host) clause = `agent.name:${host}`
    if (field === 'data.win.eventdata.targetUserName' && user) {
      clause = `data.win.eventdata.targetUserName:${user}`
    }
    if (query.includes(clause)) return
    setQueryOverride(`${query.trim()} AND ${clause}`)
  }

  function toggleHit(key: string) {
    setSelectedHits((current) =>
      current.includes(key)
        ? current.filter((item) => item !== key)
        : [...current, key],
    )
  }

  const chosenHits = hits.filter((hit, index) =>
    selectedHits.includes(hitKey(hit, index)),
  )

  async function createIncident() {
    setPromoteError(null)
    try {
      await promoteHits({ title, severity, owner, hits: chosenHits })
      setPromoteOpen(false)
      void navigate('/incidents')
    } catch (caught: unknown) {
      setPromoteError(
        caught instanceof Error ? caught.message : 'Promote failed.',
      )
    }
  }

  const windowEnd = DEMO_NOW
  const windowStart = DEMO_NOW - RANGES[range] * 60 * 60 * 1000

  return (
    <div className="min-w-0 overflow-x-hidden">
      <PageHeader
        title="Threat Hunting"
        description="Definitions are hunting/*.yml. Demo mode matches fixture events. Status stays NOT TESTED until a lab run."
      />
      <div className="grid gap-4 lg:grid-cols-[16rem_minmax(0,1fr)]">
        <section className="rounded-card border border-border bg-surface p-3">
          <label className="flex flex-col gap-1 text-xs text-text-muted">
            Search hunts
            <input
              aria-label="Search hunts"
              className={fieldClass}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </label>
          {hunts.loading ? (
            <div className="mt-3">
              <LoadingState label="Loading hunts" lines={4} />
            </div>
          ) : null}
          {hunts.error ? (
            <div className="mt-3">
              <ErrorState message={hunts.error} onRetry={hunts.reload} />
            </div>
          ) : null}
          {!hunts.loading && !hunts.error && (hunts.data?.length ?? 0) === 0 ? (
            <div className="mt-3">
              <EmptyState title="No saved hunts" />
            </div>
          ) : null}
          {!hunts.loading &&
          !hunts.error &&
          (hunts.data?.length ?? 0) > 0 &&
          visibleHunts.length === 0 ? (
            <div className="mt-3">
              <EmptyState title="No hunts match this search" />
            </div>
          ) : null}
          {!hunts.loading && !hunts.error && visibleHunts.length > 0 ? (
            <ul className="mt-3 space-y-1">
              {visibleHunts.map((hunt) => (
                <li key={hunt.id}>
                  <button
                    type="button"
                    aria-pressed={hunt.id === selected?.id}
                    className="w-full rounded-md px-2 py-2 text-left text-sm text-text hover:bg-surface-2"
                    onClick={() => choose(hunt)}
                  >
                    <span className="block">{hunt.name}</span>
                    <StatusPill kind="validation" status={hunt.status} />
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
        </section>
        <div className="min-w-0 space-y-4">
          <section className="rounded-card border border-border bg-surface p-4">
            <label className="flex flex-col gap-1 text-xs text-text-muted">
              Query
              <textarea
                aria-label="Hunt query"
                className={`${fieldClass} min-h-24 font-mono`}
                value={query}
                onChange={(event) => setQueryOverride(event.target.value)}
              />
            </label>
            <p className="mt-1 text-xs text-text-muted">
              VERIFY: OpenSearch query-string draft. Demo mode does not send it
              to an indexer.
            </p>
            <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                Time range
                <select
                  aria-label="Time range"
                  className={fieldClass}
                  value={range}
                  onChange={(event) => setRange(event.target.value as RangeKey)}
                >
                  <option value="24h">Last 24 hours</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                Host
                <select
                  aria-label="Host"
                  className={fieldClass}
                  value={host}
                  onChange={(event) => setHost(event.target.value)}
                >
                  <option value="">Any host</option>
                  {LAB_HOSTS.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                User
                <select
                  aria-label="User"
                  className={fieldClass}
                  value={user}
                  onChange={(event) => setUser(event.target.value)}
                >
                  <option value="">Any user</option>
                  {LAB_USERS.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                Event source
                <select
                  aria-label="Event source"
                  className={fieldClass}
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                >
                  <option value="">Any source</option>
                  {EVENT_SOURCES.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <button
              type="button"
              className="mt-3 rounded-md border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-accent"
              disabled={!selected}
              onClick={() => {
                if (!selected) return
                setSelectedHits([])
                void run.execute(
                  selected.id,
                  {
                    from: new Date(windowStart).toISOString(),
                    to: new Date(windowEnd).toISOString(),
                    host,
                    user,
                    source,
                  },
                  query,
                )
              }}
            >
              Run hunt
            </button>
          </section>
          {selected ? (
            <section className="rounded-card border border-border bg-surface p-4 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="font-medium text-text">{selected.name}</h2>
                <StatusPill kind="validation" status={selected.status} />
              </div>
              <dl className="mt-3 grid gap-3 md:grid-cols-2">
                <div>
                  <dt className="text-xs text-text-muted">Hypothesis</dt>
                  <dd className="text-text">{selected.hypothesis}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">Data source</dt>
                  <dd className="text-text">{selected.dataSource}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">Default window</dt>
                  <dd className="text-text">{selected.timeWindowDefault}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">
                    How this differs from the detection
                  </dt>
                  <dd className="text-text">{selected.differsFromDetections}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">Related detections</dt>
                  <dd className="flex flex-wrap gap-2">
                    {selected.relatedDetections.map((id) => (
                      <Link
                        key={id}
                        className="text-accent"
                        to={`/detections/${id}`}
                      >
                        {id}
                      </Link>
                    ))}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">Pivot fields</dt>
                  <dd className="flex flex-wrap gap-2">
                    {selected.pivotFields.map((field) => (
                      <button
                        key={field}
                        type="button"
                        className="rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-accent"
                        onClick={() => applyPivot(field)}
                      >
                        {field}
                      </button>
                    ))}
                  </dd>
                </div>
                {selected.aggregation ? (
                  <div>
                    <dt className="text-xs text-text-muted">Aggregation</dt>
                    <dd className="text-text">
                      Terms on {selected.aggregation.field}. Keep buckets
                      with doc_count at or below {selected.aggregation.maxDocCount}.
                      A query string cannot express this. Not a lab result.
                    </dd>
                  </div>
                ) : null}
                <div>
                  <dt className="text-xs text-text-muted">Expected behavior</dt>
                  <dd className="text-text">{selected.expectedBehavior}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">
                    Suspicious behavior
                  </dt>
                  <dd className="text-text">{selected.suspiciousBehavior}</dd>
                </div>
                <div>
                  <dt className="text-xs text-text-muted">MITRE</dt>
                  <dd className="text-accent">
                    {selected.mitre.map((item) => item.id).join(', ')}
                  </dd>
                </div>
                <div className="md:col-span-2">
                  <dt className="text-xs text-text-muted">
                    Investigation guidance
                  </dt>
                  <dd className="whitespace-pre-line text-text">
                    {selected.investigationGuidance}
                  </dd>
                </div>
              </dl>
            </section>
          ) : null}
          <section>
            {run.loading ? (
              <LoadingState label="Running hunt" lines={4} />
            ) : null}
            {run.error ? <ErrorState message={run.error} /> : null}
            {!run.loading && !run.error && !run.result ? (
              <EmptyState
                title="No hunt results yet"
                detail="Run a hunt to match fixture timeline events."
              />
            ) : null}
            {run.result ? (
              <div className="space-y-3">
                <p className="text-sm text-text-muted">{run.result.notice}</p>
                {selected?.aggregation ? (
                  <div className="rounded-card border border-border bg-surface p-3">
                    <h3 className="text-sm font-medium text-text">
                      Low-count buckets
                    </h3>
                    {(run.result.buckets ?? []).length === 0 ? (
                      <p className="mt-2 text-sm text-text-muted">
                        No bucket at or below {selected.aggregation.maxDocCount}.
                      </p>
                    ) : (
                      <ul className="mt-2 space-y-1 text-sm">
                        {(run.result.buckets ?? []).map((bucket) => (
                          <li key={bucket.key}>
                            <span className="font-mono text-text">{bucket.key}</span>
                            <span className="text-text-muted"> · {bucket.count}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ) : null}
                {hits.length === 0 ? (
                  <EmptyState title="No events matched" />
                ) : (
                  <>
                    <TimeSeriesChart
                      data={chart}
                      series={[
                        {
                          key: 'events',
                          label: 'Events',
                          color: 'var(--color-accent)',
                        },
                      ]}
                    />
                    <div className="flex justify-end">
                      <button
                        type="button"
                        className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
                        disabled={chosenHits.length === 0}
                        onClick={() => {
                          setPromoteError(null)
                          setPromoteOpen(true)
                        }}
                      >
                        Promote to incident
                      </button>
                    </div>
                    <div className="overflow-x-auto rounded-card border border-border bg-surface">
                      <table className="w-full border-collapse text-left text-sm">
                        <thead className="bg-surface-2 text-text-muted">
                          <tr>
                            <th className="px-3 py-2 font-medium">Select</th>
                            <th className="px-3 py-2 font-medium">Time</th>
                            <th className="px-3 py-2 font-medium">Host</th>
                            <th className="px-3 py-2 font-medium">User</th>
                            <th className="px-3 py-2 font-medium">Source</th>
                            <th className="px-3 py-2 font-medium">Event ID</th>
                            <th className="px-3 py-2 font-medium">Summary</th>
                          </tr>
                        </thead>
                        <tbody>
                          {hits.map((hit, index) => {
                            const key = hitKey(hit, index)
                            return (
                              <tr key={key} className="border-t border-border">
                                <td className="px-3 py-2 align-top">
                                  <input
                                    type="checkbox"
                                    aria-label={`Select ${hit.ruleId} ${hit.time}`}
                                    checked={selectedHits.includes(key)}
                                    onChange={() => toggleHit(key)}
                                  />
                                </td>
                                <td className="px-3 py-2 align-top">
                                  {formatLabTime(hit.time)}
                                  <div>
                                    <button
                                      type="button"
                                      className="text-xs text-accent"
                                      onClick={() =>
                                        setOpenRaw((current) =>
                                          current === key ? null : key,
                                        )
                                      }
                                    >
                                      {openRaw === key
                                        ? 'Hide raw JSON'
                                        : 'Show raw JSON'}
                                    </button>
                                    {openRaw === key ? (
                                      <pre className="mt-2 max-w-md overflow-x-auto font-mono text-xs text-text">
                                        {JSON.stringify(hit.raw, null, 2)}
                                      </pre>
                                    ) : null}
                                  </div>
                                </td>
                                <td className="px-3 py-2 align-top">
                                  <HostLink name={hit.host} />
                                </td>
                                <td className="px-3 py-2 align-top">
                                  <UserLink name={hit.user} />
                                </td>
                                <td className="px-3 py-2 align-top">
                                  {hit.source}
                                </td>
                                <td className="px-3 py-2 align-top">
                                  {hit.eventId}
                                </td>
                                <td className="px-3 py-2 align-top">
                                  {hit.title}
                                  <div className="mt-1">
                                    <SeverityBadge severity={hit.severity} />
                                  </div>
                                </td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </div>
            ) : null}
          </section>
        </div>
      </div>
      {promoteOpen ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-bg/70 p-4">
          <div
            role="dialog"
            aria-label="Promote to incident"
            className="w-full max-w-md rounded-card border border-border bg-surface p-4"
          >
            <h2 className="text-lg font-semibold text-text">
              Promote to incident
            </h2>
            <div className="mt-3 grid gap-3">
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                Title
                <input
                  aria-label="Title"
                  className={fieldClass}
                  value={title}
                  onChange={(event) => setTitleOverride(event.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                Severity
                <select
                  aria-label="Severity"
                  className={fieldClass}
                  value={severity}
                  onChange={(event) =>
                    setSeverity(event.target.value as Severity)
                  }
                >
                  {SEVERITY_OPTIONS.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-text-muted">
                Owner
                <select
                  aria-label="Owner"
                  className={fieldClass}
                  value={owner}
                  onChange={(event) => setOwner(event.target.value)}
                >
                  {INCIDENT_OWNERS.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {promoteError ? (
              <p className="mt-3 text-sm text-critical" role="alert">
                {promoteError}
              </p>
            ) : null}
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                className="rounded-md border border-border px-3 py-1.5 text-sm text-text"
                onClick={() => setPromoteOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="rounded-md border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-accent"
                onClick={() => {
                  void createIncident()
                }}
              >
                Create incident
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
