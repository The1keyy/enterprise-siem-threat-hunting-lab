import type { LucideIcon } from 'lucide-react'
import { Card } from './Card.tsx'
import { Sparkline } from './Sparkline.tsx'

type KpiCardProps = {
  label: string
  value: string | number | null
  delta?: string | null
  hint?: string
  icon?: LucideIcon
  series?: readonly number[]
  seriesColor?: string
}

export function KpiCard({
  label,
  value,
  delta,
  hint,
  icon: Icon,
  series,
  seriesColor = 'var(--color-accent)',
}: KpiCardProps) {
  return (
    <Card>
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs text-text-muted">{label}</p>
        {Icon ? (
          <Icon aria-hidden="true" size={16} className="text-text-muted" />
        ) : null}
      </div>
      <div className="mt-2 flex items-end justify-between gap-3">
        <p className="text-2xl font-semibold tabular-nums text-text">
          {value === null ? '—' : value}
        </p>
        {series && series.length > 1 ? (
          <Sparkline
            values={series}
            color={seriesColor}
            label={`${label} across the fixture window`}
          />
        ) : null}
      </div>
      {delta ? (
        <p className="mt-2 text-xs tabular-nums text-text-muted">{delta}</p>
      ) : null}
      {hint ? <p className="mt-1 text-xs text-text-muted">{hint}</p> : null}
    </Card>
  )
}
