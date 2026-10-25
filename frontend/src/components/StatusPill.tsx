import { clsx } from 'clsx'
import type { IncidentStatus, ValidationStatus } from '../types/domain.ts'

const INCIDENT_STYLE: Record<IncidentStatus, string> = {
  New: 'border-border bg-surface-2 text-text-muted',
  Investigating: 'border-accent/40 bg-accent/15 text-accent',
  Contained: 'border-medium/40 bg-medium/15 text-medium',
  Resolved: 'border-ok/40 bg-ok/15 text-ok',
  'False Positive': 'border-border bg-surface-2 text-text',
}

const VALIDATION_STYLE: Record<ValidationStatus, string> = {
  'NOT TESTED': 'border-border bg-surface-2 text-text-muted',
  'SYNTAX VALID': 'border-low/40 bg-low/15 text-low',
  'LOGTEST VALID': 'border-accent/40 bg-accent/15 text-accent',
  'LAB VALIDATED': 'border-ok/40 bg-ok/15 text-ok',
  'NEEDS TUNING': 'border-medium/40 bg-medium/15 text-medium',
}

type StatusPillProps =
  | { kind: 'incident'; status: IncidentStatus }
  | { kind: 'validation'; status: ValidationStatus }

export function StatusPill(props: StatusPillProps) {
  const className =
    props.kind === 'incident'
      ? INCIDENT_STYLE[props.status]
      : VALIDATION_STYLE[props.status]

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium',
        className,
      )}
    >
      {props.status}
    </span>
  )
}
