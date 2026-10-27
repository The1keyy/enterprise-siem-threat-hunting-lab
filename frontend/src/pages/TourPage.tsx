import { useNavigate } from 'react-router'
import { PageHeader } from '../components/PageHeader.tsx'
import { TOUR_STEPS, writeTourStep } from '../lib/tour.ts'

export function TourPage() {
  const navigate = useNavigate()

  return (
    <div className="min-w-0">
      <PageHeader
        title="Take the tour"
        description="Six short stops through the attack story. Demo fixtures are labeled. Detection rules are the real rules from the repo."
      />
      <ol className="flex max-w-3xl flex-col gap-3">
        {TOUR_STEPS.map((step, index) => (
          <li
            key={step.title}
            className="rounded-card border border-border bg-surface px-4 py-3"
          >
            <p className="text-xs text-text-muted">
              {index + 1}. {step.title}
            </p>
            <p className="mt-1 text-sm text-text">{step.body}</p>
          </li>
        ))}
      </ol>
      <button
        type="button"
        className="mt-6 rounded-md border border-accent/40 bg-accent/15 px-3 py-2 text-sm text-text transition-colors duration-150 hover:bg-accent/25"
        onClick={() => {
          writeTourStep(0)
          const first = TOUR_STEPS[0]
          if (first) navigate(first.path)
        }}
      >
        Start
      </button>
    </div>
  )
}
