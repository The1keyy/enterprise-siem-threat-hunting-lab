import { EmptyState } from '../components/EmptyState.tsx'
import { PageHeader } from '../components/PageHeader.tsx'

export function PlaceholderPage({ title }: { title: string }) {
  return (
    <>
      <PageHeader title={title} description="This page is not built yet." />
      <EmptyState title="Not built yet" />
    </>
  )
}
