import { EmptyState } from '../components/EmptyState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'

type PlaceholderPageProps = {
  title: string
  step: number
}

export function PlaceholderPage({ title, step }: PlaceholderPageProps) {
  return (
    <>
      <PageHeader title={title} description="This page is not built yet." />
      <EmptyState title={`Coming in Step ${step}`} />
    </>
  )
}
