import type { HuntAggregation, HuntBucket, HuntHit } from '../types/hunt.ts'

/**
 * Demo matcher for a hunt query_string. AND, OR, parentheses, and * wildcards.
 * This is not an OpenSearch parser. The same rules live in
 * backend/app/services/hunt_match.py.
 */
export function eventMatchesQuery(query: string, event: HuntHit): boolean {
  const raw = event.raw
  const document =
    raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  const text = query.trim()
  if (text.length === 0) return false
  return matchOr(text, document)
}

export function aggregateLowCounts(
  hits: HuntHit[],
  aggregation: HuntAggregation,
): { hits: HuntHit[]; buckets: HuntBucket[] } {
  const counts = new Map<string, number>()
  for (const hit of hits) {
    for (const value of eventValues(hit, aggregation.field)) {
      counts.set(value, (counts.get(value) ?? 0) + 1)
    }
  }
  const buckets = [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .filter((bucket) => bucket.count <= aggregation.maxDocCount)
    .sort((left, right) => left.count - right.count || left.key.localeCompare(right.key))
    .slice(0, aggregation.size)
  const keys = new Set(buckets.map((bucket) => bucket.key))
  return {
    buckets,
    hits: hits.filter((hit) =>
      eventValues(hit, aggregation.field).some((value) => keys.has(value)),
    ),
  }
}

function eventValues(event: HuntHit, field: string): string[] {
  const raw = event.raw
  const document =
    raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  return valuesAt(document, field)
}

function matchOr(expr: string, document: Record<string, unknown>): boolean {
  const text = stripParens(expr.trim())
  return splitTop(text, 'OR')
    .filter((part) => part.trim().length > 0)
    .some((part) => matchAnd(part, document))
}

function matchAnd(expr: string, document: Record<string, unknown>): boolean {
  const text = stripParens(expr.trim())
  const parts = splitTop(text, 'AND').filter((part) => part.trim().length > 0)
  return parts.length > 0 && parts.every((part) => matchTerm(part, document))
}

function matchTerm(term: string, document: Record<string, unknown>): boolean {
  const text = stripParens(term.trim())
  const splitAt = text.lastIndexOf(':')
  if (splitAt < 0) return false
  const field = text.slice(0, splitAt).trim()
  const value = text
    .slice(splitAt + 1)
    .trim()
    .replace(/^"|"$/g, '')
    .trim()
  if (field.length === 0 || value.length === 0) return false
  return valuesAt(document, field).some((item) => wildcard(value, item))
}

function valuesAt(document: Record<string, unknown>, field: string): string[] {
  let current: unknown[] = [document]
  for (const part of field.split('.')) {
    const found: unknown[] = []
    for (const item of current) {
      if (item && typeof item === 'object' && part in (item as Record<string, unknown>)) {
        found.push((item as Record<string, unknown>)[part])
      }
    }
    current = found
  }
  const values: string[] = []
  for (const item of current) {
    if (Array.isArray(item)) {
      for (const entry of item) {
        if (entry !== null && typeof entry !== 'object') values.push(String(entry))
      }
    } else if (item !== null && item !== undefined && typeof item !== 'object') {
      values.push(String(item))
    }
  }
  return values
}

function wildcard(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*')
  return new RegExp(`^${escaped}$`, 'i').test(value)
}

function stripParens(text: string): string {
  let current = text
  while (
    current.startsWith('(') &&
    current.endsWith(')') &&
    balanced(current.slice(1, -1))
  ) {
    current = current.slice(1, -1).trim()
  }
  return current
}

function balanced(text: string): boolean {
  let depth = 0
  let quote = false
  for (const char of text) {
    if (char === '"') quote = !quote
    else if (quote) continue
    else if (char === '(') depth += 1
    else if (char === ')') {
      depth -= 1
      if (depth < 0) return false
    }
  }
  return depth === 0 && !quote
}

function splitTop(expr: string, keyword: string): string[] {
  const parts: string[] = []
  let buf = ''
  let depth = 0
  let quote = false
  const token = ` ${keyword} `
  let index = 0
  while (index < expr.length) {
    const char = expr[index] ?? ''
    if (char === '"') {
      quote = !quote
      buf += char
      index += 1
      continue
    }
    if (!quote && char === '(') depth += 1
    else if (!quote && char === ')') depth = Math.max(0, depth - 1)
    if (
      depth === 0 &&
      !quote &&
      expr.slice(index, index + token.length).toUpperCase() === token
    ) {
      parts.push(buf)
      buf = ''
      index += token.length
      continue
    }
    buf += char
    index += 1
  }
  parts.push(buf)
  return parts
}
