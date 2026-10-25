import { useParams } from 'react-router'
import { PlaceholderPage } from './PlaceholderPage.tsx'

export function IncidentDetailPage() {
  const { id } = useParams()
  const title = id ? `Incident ${id}` : 'Incident'
  return <PlaceholderPage title={title} step={5} />
}
