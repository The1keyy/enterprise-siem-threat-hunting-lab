type LoadingStateProps = {
  label?: string
  lines?: number
}

export function LoadingState({
  label = 'Loading',
  lines = 3,
}: LoadingStateProps) {
  return (
    <div className="space-y-2" role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      {Array.from({ length: lines }, (_, index) => (
        <div
          key={index}
          className="h-4 animate-pulse rounded-md bg-surface-2"
          style={{ width: index === lines - 1 ? '66%' : '100%' }}
        />
      ))}
    </div>
  )
}
