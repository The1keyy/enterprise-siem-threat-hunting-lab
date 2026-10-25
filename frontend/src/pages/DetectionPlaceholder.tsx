import { useParams } from 'react-router'
import { PlaceholderPage } from './PlaceholderPage.tsx'

export function DetectionPlaceholder() {
  const { id } = useParams()
  const title = id ? `Detection ${id}` : 'Detection'
  return <PlaceholderPage title={title} step={6} />
}
