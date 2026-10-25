import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  axisTick,
  tooltipItemStyle,
  tooltipLabelStyle,
  tooltipStyle,
} from './chartTheme.ts'

export type BarListItem = {
  label: string
  value: number
}

type BarListProps = {
  items: readonly BarListItem[]
  color?: string
  labelWidth?: number
}

export function BarList({
  items,
  color = 'var(--color-accent)',
  labelWidth = 112,
}: BarListProps) {
  const data = items.map((item) => ({ ...item }))
  const height = Math.max(140, items.length * 36)

  return (
    <div className="min-w-0">
      <ul className="sr-only">
        {items.map((item) => (
          <li key={item.label}>
            {item.label}: {item.value}
          </li>
        ))}
      </ul>
      <div className="min-w-0" style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 16, left: 0, bottom: 0 }}
          >
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="label"
              width={labelWidth}
              tick={axisTick}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={tooltipStyle}
              labelStyle={tooltipLabelStyle}
              itemStyle={tooltipItemStyle}
            />
            <Bar
              dataKey="value"
              name="Count"
              fill={color}
              radius={2}
              barSize={12}
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
