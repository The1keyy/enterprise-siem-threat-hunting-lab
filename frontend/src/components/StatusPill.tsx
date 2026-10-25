import { clsx } from 'clsx'
import type {
  HealthStatus,
  IncidentStatus,
  ValidationStatus,
} from '../types/domain.ts'

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

const HEALTH_STYLE: Record<HealthStatus, string> = {
  Healthy: 'border-ok/40 bg-ok/15 text-ok',
  Degraded: 'border-medium/40 bg-medium/15 text-medium',
  Offline: 'border-critical/40 bg-critical/15 text-critical',
}

type StatusPillProps =
  | { kind: 'incident'; status: IncidentStatus }
  | { kind: 'validation'; status: ValidationStatus }
  | { kind: 'health'; status: HealthStatus }

function pillStyle(props: StatusPillProps): string {
  if (props.kind === 'incident') return INCIDENT_STYLE[props.status]
  if (props.kind === 'validation') return VALIDATION_STYLE[props.status]
  return HEALTH_STYLE[props.status]
}

export function StatusPill(props: StatusPillProps) {
  const className = pillStyle(props)

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
