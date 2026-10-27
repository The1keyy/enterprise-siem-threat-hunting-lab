import { clsx } from 'clsx'

type LoadingStateProps = {
  label?: string
  lines?: number
  layout?: 'lines' | 'kpis' | 'table'
}

function Bar({ className }: { className?: string }) {
  return (
    <div className={clsx('animate-pulse rounded-md bg-surface-2', className)} />
  )
}

export function LoadingState({
  label = 'Loading',
  lines = 3,
  layout = 'lines',
}: LoadingStateProps) {
  if (layout === 'kpis') {
    return (
      <div
        className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-4"
        role="status"
        aria-busy="true"
      >
        <span className="sr-only">{label}</span>
        {Array.from({ length: 4 }, (_, index) => (
          <div
            key={index}
            className="rounded-card border border-border bg-surface p-4"
          >
            <Bar className="h-3 w-24" />
            <Bar className="mt-3 h-8 w-16" />
          </div>
        ))}
      </div>
    )
  }

  if (layout === 'table') {
    return (
      <div
        className="overflow-hidden rounded-card border border-border"
        role="status"
        aria-busy="true"
      >
        <span className="sr-only">{label}</span>
        <Bar className="h-9 rounded-none" />
        {Array.from({ length: lines }, (_, index) => (
          <Bar key={index} className="h-10 rounded-none border-t border-border" />
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-2" role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      {Array.from({ length: lines }, (_, index) => (
        <Bar
          key={index}
          className={clsx('h-4', index === lines - 1 ? 'w-2/3' : 'w-full')}
        />
      ))}
    </div>
  )
}
