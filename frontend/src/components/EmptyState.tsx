type EmptyStateProps = {
  title: string
  detail?: string
}

export function EmptyState({
  title,
  detail = 'No data yet.',
}: EmptyStateProps) {
  return (
    <div className="rounded-card border border-dashed border-border bg-surface px-4 py-8 text-center">
      <p className="text-sm font-medium text-text">{title}</p>
      <p className="mt-1 text-sm text-text-muted">{detail}</p>
    </div>
  )
}
