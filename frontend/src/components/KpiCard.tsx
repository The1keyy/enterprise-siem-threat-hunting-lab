import type { LucideIcon } from 'lucide-react'
import { Card } from './Card.tsx'

type KpiCardProps = {
  label: string
  value: string | number | null
  delta?: string | null
  hint?: string
  icon?: LucideIcon
}

export function KpiCard({
  label,
  value,
  delta,
  hint,
  icon: Icon,
}: KpiCardProps) {
  return (
    <Card>
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm text-text-muted">{label}</p>
        {Icon ? (
          <Icon aria-hidden="true" size={16} className="text-text-muted" />
        ) : null}
      </div>
      <p className="mt-2 text-2xl font-semibold text-text">
        {value === null ? '—' : value}
      </p>
      {delta ? <p className="mt-1 text-xs text-text-muted">{delta}</p> : null}
      {hint ? <p className="mt-1 text-xs text-text-muted">{hint}</p> : null}
    </Card>
  )
}
