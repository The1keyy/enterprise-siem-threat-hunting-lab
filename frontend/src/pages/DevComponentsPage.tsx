import { useState } from 'react'
import { Activity } from 'lucide-react'
import { Card } from '../components/Card.tsx'
import { DataTable, type DataTableColumn } from '../components/DataTable.tsx'
import { DemoBanner } from '../components/DemoBanner.tsx'
import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { KpiCard } from '../components/KpiCard.tsx'
import { LabOnlyTag } from '../components/LabOnlyTag.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { SeverityBadge } from '../components/SeverityBadge.tsx'
import { StatusPill } from '../components/StatusPill.tsx'
import { useDataMode } from '../hooks/useDataMode.ts'
import {
  INCIDENT_STATUSES,
  SEVERITIES,
  VALIDATION_STATUSES,
} from '../types/domain.ts'

type SampleRow = {
  id: string
  name: string
  note: string
}

const SAMPLE_ROWS: readonly SampleRow[] = [
  { id: 'a', name: 'Layout sample A', note: 'Not telemetry' },
  { id: 'b', name: 'Layout sample B', note: 'Not telemetry' },
]

const SAMPLE_COLUMNS: readonly DataTableColumn<SampleRow>[] = [
  { id: 'name', header: 'Name', accessor: (row) => row.name },
  { id: 'note', header: 'Note', accessor: (row) => row.note },
]

export default function DevComponentsPage() {
  const mode = useDataMode()
  const [selected, setSelected] = useState<string | null>(null)
  const [retried, setRetried] = useState(false)

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Component gallery"
        description="Dev-only preview. Labels here are layout samples, not telemetry."
      />
      <p className="text-sm text-text-muted">Data mode: {mode}</p>

      <Card title="Demo banner">
        <DemoBanner />
      </Card>

      <Card title="KPI cards">
        <div className="grid gap-3 md:grid-cols-3">
          <KpiCard label="Empty value" value={null} />
          <KpiCard
            label="Text value"
            value="Sample"
            delta="layout only"
            icon={Activity}
          />
          <KpiCard label="No delta" value={null} delta={null} />
        </div>
      </Card>

      <Card title="Severity">
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((severity) => (
            <SeverityBadge key={severity} severity={severity} />
          ))}
        </div>
      </Card>

      <Card title="Incident status">
        <div className="flex flex-wrap gap-2">
          {INCIDENT_STATUSES.map((status) => (
            <StatusPill key={status} kind="incident" status={status} />
          ))}
        </div>
      </Card>

      <Card title="Validation status">
        <div className="flex flex-wrap gap-2">
          {VALIDATION_STATUSES.map((status) => (
            <StatusPill key={status} kind="validation" status={status} />
          ))}
        </div>
      </Card>

      <Card title="Tags">
        <LabOnlyTag />
      </Card>

      <Card title="Table">
        <DataTable
          columns={SAMPLE_COLUMNS}
          rows={SAMPLE_ROWS}
          getRowId={(row) => row.id}
          onRowActivate={(row) => setSelected(row.name)}
        />
        <p className="mt-2 text-sm text-text-muted">
          Selected: {selected ?? 'none'}
        </p>
      </Card>

      <Card title="Empty table">
        <DataTable
          columns={SAMPLE_COLUMNS}
          rows={[]}
          getRowId={(row) => row.id}
        />
      </Card>

      <Card title="Empty, error, and loading">
        <div className="flex flex-col gap-3">
          <EmptyState title="Coming in Step 4" />
          <ErrorState
            message={
              retried
                ? 'Retry clicked. Still a preview.'
                : 'Example error message.'
            }
            onRetry={() => setRetried(true)}
          />
          <LoadingState />
        </div>
      </Card>
    </div>
  )
}
