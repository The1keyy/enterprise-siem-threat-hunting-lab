import { useMemo, useState } from 'react'
import { clsx } from 'clsx'
import { EmptyState } from './EmptyState.tsx'

export type DataTableColumn<T> = {
  id: string
  header: string
  accessor: (row: T) => string | number
}

type DataTableProps<T> = {
  columns: readonly DataTableColumn<T>[]
  rows: readonly T[]
  getRowId: (row: T) => string
  onRowActivate?: (row: T) => void
  emptyTitle?: string
}

type SortState = {
  id: string
  direction: 'asc' | 'desc'
}

function compareValues(left: string | number, right: string | number): number {
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right
  }
  return String(left).localeCompare(String(right))
}

export function DataTable<T>({
  columns,
  rows,
  getRowId,
  onRowActivate,
  emptyTitle = 'No data yet',
}: DataTableProps<T>) {
  const [sort, setSort] = useState<SortState | null>(null)

  const sortedRows = useMemo(() => {
    if (!sort) {
      return rows
    }
    const column = columns.find((item) => item.id === sort.id)
    if (!column) {
      return rows
    }
    const next = [...rows]
    next.sort((left, right) => {
      const result = compareValues(
        column.accessor(left),
        column.accessor(right),
      )
      return sort.direction === 'asc' ? result : -result
    })
    return next
  }, [columns, rows, sort])

  function toggleSort(id: string) {
    setSort((current) => {
      if (!current || current.id !== id) {
        return { id, direction: 'asc' }
      }
      if (current.direction === 'asc') {
        return { id, direction: 'desc' }
      }
      return null
    })
  }

  return (
    <div className="overflow-x-auto rounded-card border border-border bg-surface">
      <table className="w-full border-collapse text-left text-sm">
        <thead className="bg-surface-2 text-text-muted">
          <tr>
            {columns.map((column) => {
              const active = sort?.id === column.id
              const ariaSort = active
                ? sort.direction === 'asc'
                  ? 'ascending'
                  : 'descending'
                : 'none'
              return (
                <th
                  key={column.id}
                  scope="col"
                  aria-sort={ariaSort}
                  className="px-3 py-2 font-medium"
                >
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 rounded-sm text-text-muted"
                    onClick={() => toggleSort(column.id)}
                  >
                    {column.header}
                    <span aria-hidden="true" className="text-xs">
                      {active ? (sort.direction === 'asc' ? '↑' : '↓') : '↕'}
                    </span>
                  </button>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {sortedRows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="p-3">
                <EmptyState title={emptyTitle} />
              </td>
            </tr>
          ) : (
            sortedRows.map((row) => (
              <tr
                key={getRowId(row)}
                tabIndex={0}
                className={clsx(
                  'border-t border-border text-text',
                  onRowActivate && 'cursor-pointer hover:bg-surface-2',
                )}
                onClick={() => onRowActivate?.(row)}
                onKeyDown={(event) => {
                  if (!onRowActivate) {
                    return
                  }
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onRowActivate(row)
                  }
                }}
              >
                {columns.map((column) => (
                  <td key={column.id} className="px-3 py-2">
                    {column.accessor(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
