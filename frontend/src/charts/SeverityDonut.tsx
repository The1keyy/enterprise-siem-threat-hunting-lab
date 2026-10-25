import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import type { SeverityTotal } from '../types/overview.ts'
import {
  severityColor,
  severityLabel,
  tooltipItemStyle,
  tooltipLabelStyle,
  tooltipStyle,
} from './chartTheme.ts'

type SeverityDonutProps = {
  slices: readonly SeverityTotal[]
}

export function SeverityDonut({ slices }: SeverityDonutProps) {
  const total = slices.reduce((sum, slice) => sum + slice.count, 0)
  const data = slices.map((slice) => ({
    name: severityLabel[slice.severity],
    count: slice.count,
    severity: slice.severity,
  }))

  return (
    <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:items-center">
      <div className="h-48 min-w-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="count"
              nameKey="name"
              innerRadius={48}
              outerRadius={72}
              paddingAngle={2}
              isAnimationActive={false}
              stroke="var(--color-surface)"
            >
              {data.map((slice) => (
                <Cell
                  key={slice.severity}
                  fill={severityColor[slice.severity]}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={tooltipStyle}
              labelStyle={tooltipLabelStyle}
              itemStyle={tooltipItemStyle}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <ul className="flex flex-col gap-2">
        <li className="text-sm text-text">{total} alerts</li>
        {slices.map((slice) => (
          <li key={slice.severity} className="flex items-center gap-2">
            <SeverityBadge severity={slice.severity} />
            <span className="text-sm text-text">{slice.count}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
