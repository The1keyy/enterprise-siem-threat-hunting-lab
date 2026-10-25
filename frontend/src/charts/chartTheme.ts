import type { CSSProperties } from 'react'
import type { AlertSeverity } from '../types/overview.ts'

export const severityColor: Record<AlertSeverity, string> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
}

export const severityLabel: Record<AlertSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export const axisTick = {
  fill: 'var(--color-text-muted)',
  fontSize: 12,
} as const

export const axisLine = { stroke: 'var(--color-border)' }

export const tooltipStyle: CSSProperties = {
  background: 'var(--color-surface)',
  border: '1px solid var(--color-border)',
  borderRadius: 8,
  color: 'var(--color-text)',
  fontSize: 12,
}

export const tooltipLabelStyle: CSSProperties = {
  color: 'var(--color-text)',
}

export const tooltipItemStyle: CSSProperties = {
  color: 'var(--color-text)',
}
