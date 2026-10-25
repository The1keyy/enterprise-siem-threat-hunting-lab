import { useState } from 'react'
import { Link } from 'react-router'
import { detectionName } from '../../lib/detectionCatalog.ts'
import {
  readAuth,
  readProcess,
  type AuthView,
  type ProcessView,
} from '../../lib/evidenceFields.ts'
import type { TimelineEvent } from '../../types/incident.ts'

type EvidenceTab = 'raw' | 'process' | 'auth' | 'detections'

const TABS: { id: EvidenceTab; label: string }[] = [
  { id: 'raw', label: 'Raw Event' },
  { id: 'process', label: 'Process' },
  { id: 'auth', label: 'Authentication' },
  { id: 'detections', label: 'Related Detections' },
]

type EvidencePanelProps = {
  event: TimelineEvent | null
  ruleIds: readonly string[]
}

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <dt className="text-xs text-text-muted">{label}</dt>
      <dd className="text-sm break-all text-text">{value ?? 'No data yet'}</dd>
    </div>
  )
}

function ProcessFields({ view }: { view: ProcessView | null }) {
  if (!view) {
    return <p className="text-sm text-text-muted">No data yet</p>
  }
  return (
    <dl className="space-y-2">
      <Field label="Image" value={view.image} />
      <Field label="Command line" value={view.commandLine} />
      <Field label="Parent" value={view.parent} />
    </dl>
  )
}

function AuthFields({ view }: { view: AuthView | null }) {
  if (!view) {
    return <p className="text-sm text-text-muted">No data yet</p>
  }
  return (
    <dl className="space-y-2">
      <Field label="Logon type" value={view.logonType} />
      <Field label="Source IP" value={view.sourceIp} />
      <Field label="Account" value={view.account} />
    </dl>
  )
}

export function EvidencePanel({ event, ruleIds }: EvidencePanelProps) {
  const [tab, setTab] = useState<EvidenceTab>('raw')
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>(
    'idle',
  )

  async function copyRaw() {
    if (!event) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(event.raw, null, 2))
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
  }

  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-2" role="tablist">
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            className={
              tab === item.id
                ? 'rounded-md border border-accent/40 bg-accent/15 px-2 py-1 text-xs text-accent'
                : 'rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-text-muted'
            }
            onClick={() => {
              setTab(item.id)
              setCopyState('idle')
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
      {!event ? <p className="text-sm text-text-muted">No data yet</p> : null}
      {event && tab === 'raw' ? (
        <div>
          <button
            type="button"
            className="mb-2 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-text"
            onClick={() => void copyRaw()}
          >
            Copy JSON
          </button>
          {copyState === 'copied' ? (
            <span className="ml-2 text-xs text-text-muted">Copied</span>
          ) : null}
          {copyState === 'failed' ? (
            <span className="ml-2 text-xs text-text-muted">
              Copy failed. Select the JSON below.
            </span>
          ) : null}
          <pre className="max-h-80 overflow-auto rounded-md border border-border bg-surface-2 p-3 text-xs text-text">
            {JSON.stringify(event.raw, null, 2)}
          </pre>
        </div>
      ) : null}
      {event && tab === 'process' ? (
        <ProcessFields view={readProcess(event.raw)} />
      ) : null}
      {event && tab === 'auth' ? (
        <AuthFields view={readAuth(event.raw)} />
      ) : null}
      {event && tab === 'detections' ? (
        <ul className="space-y-2">
          {ruleIds.map((ruleId) => (
            <li key={ruleId}>
              <Link
                className="text-sm text-accent"
                to={`/detections/${ruleId}`}
              >
                {ruleId}
              </Link>
              <span className="ml-2 text-sm text-text">
                {detectionName(ruleId)}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
