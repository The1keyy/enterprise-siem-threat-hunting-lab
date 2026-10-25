import { Link } from 'react-router'

function stop(event: { stopPropagation: () => void }) {
  event.stopPropagation()
}

export function UserLink({ name }: { name: string }) {
  return (
    <Link
      to={`/entities/users/${encodeURIComponent(name)}`}
      className="text-accent"
      onClick={stop}
    >
      {name}
    </Link>
  )
}

export function HostLink({ name }: { name: string }) {
  return (
    <Link
      to={`/entities/hosts/${encodeURIComponent(name)}`}
      className="text-accent"
      onClick={stop}
    >
      {name}
    </Link>
  )
}
