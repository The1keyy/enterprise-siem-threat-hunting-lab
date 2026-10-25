import { useEffect, useId, useRef, useState } from 'react'
import { LabOnlyTag } from '../LabOnlyTag.tsx'
import { formatLabTime } from '../../lib/formatLabTime.ts'
import type {
  ResponseActionName,
  ResponseAuditEntry,
} from '../../types/incident.ts'

type ActionSpec = {
  name: ResponseActionName
  target: string | null
}

type ResponseActionsProps = {
  actions: readonly ActionSpec[]
  audit: readonly ResponseAuditEntry[]
  onConfirm: (action: ResponseActionName, target: string) => Promise<void>
}

export function ResponseActions({
  actions,
  audit,
  onConfirm,
}: ResponseActionsProps) {
  const [pending, setPending] = useState<ActionSpec | null>(null)
  const [busy, setBusy] = useState(false)
  const titleId = useId()
  const confirmRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (pending) confirmRef.current?.focus()
  }, [pending])

  async function confirm() {
    if (!pending?.target || busy) return
    setBusy(true)
    try {
      await onConfirm(pending.name, pending.target)
      setPending(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <ul className="space-y-2">
        {actions.map((action) => (
          <li key={action.name} className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text disabled:opacity-50"
              disabled={!action.target}
              onClick={() => setPending(action)}
            >
              {action.name}
            </button>
            <LabOnlyTag />
            {action.target ? null : (
              <span className="text-xs text-text-muted">No data yet</span>
            )}
          </li>
        ))}
      </ul>
      {audit.length > 0 ? (
        <ul className="mt-3 space-y-2 border-t border-border pt-3">
          {audit.map((entry) => (
            <li key={entry.id} className="text-xs text-text-muted">
              <span className="text-text">
                {formatLabTime(entry.time)} · {entry.action} · {entry.target}
              </span>
              <span className="mt-1 block text-text">{entry.message}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-xs text-text-muted">No dry runs yet.</p>
      )}
      {pending?.target ? (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center bg-bg/80 p-4"
          role="presentation"
          onClick={() => setPending(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            className="w-full max-w-md rounded-card border border-border bg-surface p-4 shadow-card"
            onClick={(event) => event.stopPropagation()}
            onKeyDown={(event) => {
              if (event.key === 'Escape') setPending(null)
            }}
          >
            <h3 id={titleId} className="text-sm font-medium text-text">
              Confirm lab-only dry run
            </h3>
            <p className="mt-2 text-sm text-text">
              {pending.name} on {pending.target}.
            </p>
            <p className="mt-1 text-xs text-text-muted">
              Confirming records a dry run. It does not run the action.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                className="rounded-md border border-border px-3 py-1.5 text-sm text-text"
                onClick={() => setPending(null)}
              >
                Cancel
              </button>
              <button
                ref={confirmRef}
                type="button"
                className="rounded-md border border-medium/40 bg-medium/15 px-3 py-1.5 text-sm text-medium"
                onClick={() => void confirm()}
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
