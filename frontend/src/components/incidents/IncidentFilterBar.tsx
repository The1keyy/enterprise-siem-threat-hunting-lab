import { INCIDENT_STATUSES, SEVERITIES } from '../../types/domain.ts'
import {
  LAB_HOSTS,
  TECHNIQUE_OPTIONS,
  type IncidentFilters,
} from '../../lib/incidentFilters.ts'

const fieldClass =
  'rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text'

type IncidentFilterBarProps = {
  filters: IncidentFilters
  onChange: (filters: IncidentFilters) => void
  onClear: () => void
}

function toggleValue<T extends string>(values: readonly T[], value: T): T[] {
  return values.includes(value)
    ? values.filter((item) => item !== value)
    : [...values, value]
}

export function IncidentFilterBar({
  filters,
  onChange,
  onClear,
}: IncidentFilterBarProps) {
  return (
    <div className="rounded-card border border-border bg-surface p-3">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <fieldset className="min-w-0">
          <legend className="mb-1 text-xs font-medium text-text-muted">
            Severity
          </legend>
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((severity) => (
              <label
                key={severity}
                className="inline-flex items-center gap-1 text-xs text-text"
              >
                <input
                  type="checkbox"
                  checked={filters.severities.includes(severity)}
                  onChange={() =>
                    onChange({
                      ...filters,
                      severities: toggleValue(filters.severities, severity),
                    })
                  }
                />
                {severity.charAt(0).toUpperCase() + severity.slice(1)}
              </label>
            ))}
          </div>
        </fieldset>
        <fieldset className="min-w-0">
          <legend className="mb-1 text-xs font-medium text-text-muted">
            Status
          </legend>
          <div className="flex flex-wrap gap-2">
            {INCIDENT_STATUSES.map((status) => (
              <label
                key={status}
                className="inline-flex items-center gap-1 text-xs text-text"
              >
                <input
                  type="checkbox"
                  checked={filters.statuses.includes(status)}
                  onChange={() =>
                    onChange({
                      ...filters,
                      statuses: toggleValue(filters.statuses, status),
                    })
                  }
                />
                {status}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="flex min-w-0 flex-col gap-1 text-xs text-text-muted">
          User
          <input
            className={fieldClass}
            value={filters.user}
            autoComplete="off"
            onChange={(event) =>
              onChange({ ...filters, user: event.target.value })
            }
          />
        </label>
        <label className="flex min-w-0 flex-col gap-1 text-xs text-text-muted">
          Host
          <select
            className={fieldClass}
            value={filters.host}
            onChange={(event) =>
              onChange({ ...filters, host: event.target.value })
            }
          >
            <option value="">Any host</option>
            {LAB_HOSTS.map((host) => (
              <option key={host} value={host}>
                {host}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1 text-xs text-text-muted">
          MITRE technique
          <select
            className={fieldClass}
            value={filters.technique}
            onChange={(event) =>
              onChange({ ...filters, technique: event.target.value })
            }
          >
            <option value="">Any technique</option>
            {TECHNIQUE_OPTIONS.map((item) => (
              <option key={item.id} value={item.id}>
                {item.id} {item.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1 text-xs text-text-muted">
          From
          <input
            type="date"
            className={fieldClass}
            value={filters.from}
            onChange={(event) =>
              onChange({ ...filters, from: event.target.value })
            }
          />
        </label>
        <label className="flex min-w-0 flex-col gap-1 text-xs text-text-muted">
          To
          <input
            type="date"
            className={fieldClass}
            value={filters.to}
            onChange={(event) =>
              onChange({ ...filters, to: event.target.value })
            }
          />
        </label>
        <div className="flex items-end">
          <button
            type="button"
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
            onClick={onClear}
          >
            Clear filters
          </button>
        </div>
      </div>
    </div>
  )
}
