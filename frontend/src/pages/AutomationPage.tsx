import { EmptyState } from '../components/EmptyState.tsx'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'
import { useResource } from '../hooks/useResource.ts'
import { listWorkflows } from '../services/api.ts'

export function AutomationPage() {
  const state = useResource(
    listWorkflows,
    'automation',
    'The automation request failed.',
  )

  return (
    <div className="min-w-0 overflow-x-hidden">
      <p className="mb-3 text-sm font-medium text-text">
        Escalation is implemented. Enrichment and context stay stretch. No
        response action runs.
      </p>
      <PageHeader
        title="Automation"
        description="A new incident or a higher risk band writes an analyst checklist. Nothing is isolated or disabled."
      />
      {state.loading ? (
        <LoadingState label="Loading workflows" lines={4} />
      ) : null}
      {state.error ? (
        <ErrorState message={state.error} onRetry={state.reload} />
      ) : null}
      {!state.loading && !state.error && (state.data?.length ?? 0) === 0 ? (
        <EmptyState title="No workflows yet" />
      ) : null}
      {state.data && state.data.length > 0 ? (
        <div className="grid gap-3">
          {state.data.map((workflow) => (
            <article
              key={workflow.id}
              className="rounded-card border border-border bg-surface p-4"
            >
              <h2 className="text-sm font-medium text-text">{workflow.name}</h2>
              <p className="mt-1 text-sm text-text-muted">
                Trigger: {workflow.trigger}
              </p>
              <ol className="mt-3 flex flex-wrap items-center gap-2">
                {workflow.steps.map((step, index) => (
                  <li key={step} className="flex items-center gap-2">
                    <span className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-text">
                      {step}
                    </span>
                    {index < workflow.steps.length - 1 ? (
                      <span aria-hidden="true" className="text-text-muted">
                        →
                      </span>
                    ) : null}
                  </li>
                ))}
              </ol>
              <p className="mt-3 text-sm text-text">{workflow.destructive}</p>
              <p className="mt-1 text-sm text-text-muted">{workflow.status}</p>
            </article>
          ))}
        </div>
      ) : null}
    </div>
  )
}
