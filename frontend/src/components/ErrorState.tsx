type ErrorStateProps = {
  title?: string
  message: string
  onRetry?: () => void
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
}: ErrorStateProps) {
  return (
    <div
      className="rounded-card border border-critical/40 bg-surface px-4 py-6"
      role="alert"
    >
      <p className="text-sm font-medium text-critical">{title}</p>
      <p className="mt-1 text-sm text-text">{message}</p>
      {onRetry ? (
        <button
          type="button"
          className="mt-3 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
          onClick={onRetry}
        >
          Retry
        </button>
      ) : null}
    </div>
  )
}
