import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { useDetections } from '../hooks/useDetections.ts'
import { useIncidents } from '../hooks/useIncidents.ts'
import { EMPTY_FILTERS } from '../lib/incidentFilters.ts'
import { NAV_ITEMS } from '../navigation.ts'

type PaletteItem = {
  id: string
  label: string
  hint: string
  to: string
}

type CommandPaletteProps = {
  onClose: () => void
}

export function CommandPalette({ onClose }: CommandPaletteProps) {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const incidents = useIncidents(EMPTY_FILTERS)
  const detections = useDetections()

  const items = useMemo(() => {
    const pages: PaletteItem[] = [
      ...NAV_ITEMS.map((item) => ({
        id: `page-${item.to}`,
        label: item.label,
        hint: 'Page',
        to: item.to,
      })),
      {
        id: 'page-about',
        label: 'About',
        hint: 'Page',
        to: '/about',
      },
      {
        id: 'page-tour',
        label: 'Take the tour',
        hint: 'Page',
        to: '/tour',
      },
    ]
    const cases: PaletteItem[] = (incidents.data ?? []).map((item) => ({
      id: `incident-${item.id}`,
      label: `${item.id} ${item.title}`,
      hint: 'Incident',
      to: `/incidents/${item.id}`,
    }))
    const rules: PaletteItem[] = (detections.data ?? []).map((item) => ({
      id: `detection-${item.id}`,
      label: `${item.id} ${item.name}`,
      hint: 'Detection',
      to: `/detections/${item.id}`,
    }))
    const needle = query.trim().toLowerCase()
    return [...pages, ...cases, ...rules].filter((item) =>
      needle.length === 0
        ? true
        : `${item.label} ${item.hint}`.toLowerCase().includes(needle),
    )
  }, [detections.data, incidents.data, query])

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const selected = items.length === 0 ? 0 : Math.min(active, items.length - 1)

  function choose(item: PaletteItem | undefined) {
    if (!item) return
    navigate(item.to)
    onClose()
  }

  return (
    <div className="fixed inset-0 z-40 bg-bg/70 p-4" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Jump to a page, incident, or detection"
        className="mx-auto mt-12 w-full max-w-lg overflow-hidden rounded-card border border-border bg-surface shadow-card"
        onClick={(event) => event.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={query}
          aria-label="Search pages, incidents, and detections"
          placeholder="Pages, incidents, detections"
          className="w-full border-b border-border bg-surface px-4 py-3 text-sm text-text outline-none"
          onChange={(event) => {
            setQuery(event.target.value)
            setActive(0)
          }}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.preventDefault()
              onClose()
            } else if (event.key === 'ArrowDown') {
              event.preventDefault()
              setActive((current) =>
                items.length === 0 ? 0 : (current + 1) % items.length,
              )
            } else if (event.key === 'ArrowUp') {
              event.preventDefault()
              setActive((current) =>
                items.length === 0
                  ? 0
                  : (current - 1 + items.length) % items.length,
              )
            } else if (event.key === 'Enter') {
              event.preventDefault()
              choose(items[selected])
            }
          }}
        />
        <ul className="max-h-80 overflow-y-auto py-1">
          {items.length === 0 ? (
            <li className="px-4 py-3 text-sm text-text-muted">No matches</li>
          ) : (
            items.map((item, index) => (
              <li key={item.id}>
                <button
                  type="button"
                  className={
                    index === selected
                      ? 'flex w-full items-center justify-between gap-3 bg-surface-2 px-4 py-2 text-left text-sm text-text'
                      : 'flex w-full items-center justify-between gap-3 px-4 py-2 text-left text-sm text-text transition-colors duration-150 hover:bg-surface-2'
                  }
                  onMouseEnter={() => setActive(index)}
                  onClick={() => choose(item)}
                >
                  <span className="min-w-0 truncate">{item.label}</span>
                  <span className="shrink-0 text-xs text-text-muted">
                    {item.hint}
                  </span>
                </button>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  )
}
