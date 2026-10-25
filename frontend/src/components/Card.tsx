import type { ReactNode } from 'react'
import { clsx } from 'clsx'

type CardProps = {
  title?: string
  children: ReactNode
  className?: string
}

export function Card({ title, children, className }: CardProps) {
  return (
    <section
      className={clsx(
        'rounded-card border border-border bg-surface p-4 shadow-card',
        className,
      )}
    >
      {title ? (
        <h2 className="mb-3 text-sm font-medium text-text">{title}</h2>
      ) : null}
      {children}
    </section>
  )
}
