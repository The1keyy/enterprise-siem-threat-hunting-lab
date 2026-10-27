import type { ReactNode } from 'react'
import { clsx } from 'clsx'

type CardProps = {
  title?: string
  subtitle?: string
  action?: ReactNode
  children: ReactNode
  className?: string
}

export function Card({
  title,
  subtitle,
  action,
  children,
  className,
}: CardProps) {
  return (
    <section
      className={clsx(
        'flex h-full flex-col rounded-card border border-border bg-surface p-4 shadow-card',
        className,
      )}
    >
      {title ? (
        <header className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-sm font-medium text-text">{title}</h2>
            {subtitle ? (
              <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>
            ) : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </header>
      ) : null}
      <div className="min-w-0 flex-1">{children}</div>
    </section>
  )
}
