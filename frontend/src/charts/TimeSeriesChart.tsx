import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  axisLine,
  axisTick,
  tooltipItemStyle,
  tooltipLabelStyle,
  tooltipStyle,
} from './chartTheme.ts'

export type TimeSeriesPoint = {
  label: string
  [key: string]: string | number
}

export type TimeSeriesSeries = {
  key: string
  label: string
  color: string
}

type TimeSeriesChartProps = {
  data: readonly TimeSeriesPoint[]
  series: readonly TimeSeriesSeries[]
  stacked?: boolean
  variant?: 'area' | 'line'
}

export function TimeSeriesChart({
  data,
  series,
  stacked = false,
  variant = 'area',
}: TimeSeriesChartProps) {
  const chartData = data.map((point) => ({ ...point }))

  return (
    <div className="min-w-0">
      <ul className="mb-2 flex flex-wrap gap-2">
        {series.map((item) => (
          <li
            key={item.key}
            className="inline-flex items-center gap-1 text-xs text-text"
          >
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 rounded-sm"
              style={{ background: item.color }}
            />
            {item.label}
          </li>
        ))}
      </ul>
      <div className="h-56 min-w-0">
        <ResponsiveContainer width="100%" height="100%">
          {variant === 'line' ? (
            <LineChart
              data={chartData}
              margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
            >
              <CartesianGrid
                stroke="var(--color-border)"
                strokeOpacity={0.55}
                strokeDasharray="3 6"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                tick={axisTick}
                axisLine={axisLine}
                tickLine={axisLine}
              />
              <YAxis
                width={32}
                tick={axisTick}
                axisLine={axisLine}
                tickLine={axisLine}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={tooltipStyle}
                labelStyle={tooltipLabelStyle}
                itemStyle={tooltipItemStyle}
              />
              {series.map((item) => (
                <Line
                  key={item.key}
                  type="monotone"
                  dataKey={item.key}
                  name={item.label}
                  stroke={item.color}
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          ) : (
            <AreaChart
              data={chartData}
              margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
            >
              <CartesianGrid
                stroke="var(--color-border)"
                strokeOpacity={0.55}
                strokeDasharray="3 6"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                tick={axisTick}
                axisLine={axisLine}
                tickLine={axisLine}
              />
              <YAxis
                width={32}
                tick={axisTick}
                axisLine={axisLine}
                tickLine={axisLine}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={tooltipStyle}
                labelStyle={tooltipLabelStyle}
                itemStyle={tooltipItemStyle}
              />
              {series.map((item) => (
                <Area
                  key={item.key}
                  type="monotone"
                  dataKey={item.key}
                  name={item.label}
                  stroke={item.color}
                  fill={item.color}
                  fillOpacity={0.14}
                  stackId={stacked ? 'alerts' : undefined}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  )
}
