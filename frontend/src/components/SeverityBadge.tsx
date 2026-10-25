import { clsx } from 'clsx'
import type { Severity } from '../types/domain.ts'

const LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

const STYLE: Record<Severity, string> = {
  critical: 'border-critical/40 bg-critical/15 text-critical',
  high: 'border-high/40 bg-high/15 text-high',
  medium: 'border-medium/40 bg-medium/15 text-medium',
  low: 'border-low/40 bg-low/15 text-low',
  info: 'border-accent/40 bg-accent/15 text-accent',
}

type SeverityBadgeProps = {
  severity: Severity
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium',
        STYLE[severity],
      )}
    >
      {LABEL[severity]}
    </span>
  )
}
