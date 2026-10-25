import type { HuntHit } from '../types/hunt.ts'

/** Demo matcher for a query-string draft. This is not an OpenSearch parser. */
export function eventMatchesQuery(query: string, event: HuntHit): boolean {
  const blob = [
    event.title,
    event.ruleId,
    event.source,
    event.eventId,
    event.host,
    event.user,
    JSON.stringify(event.raw),
  ]
    .join(' ')
    .toLowerCase()
  const clauses = query.split(/\s+OR\s+/i)
  return clauses.some((clause) => {
    const terms = clause.split(/\s+AND\s+/i).map((term) => {
      const value = term.includes(':')
        ? term.slice(term.lastIndexOf(':') + 1)
        : term
      return value.replace(/["()]/g, '').trim().toLowerCase()
    })
    return terms.every((term) => term.length > 2 && blob.includes(term))
  })
}
