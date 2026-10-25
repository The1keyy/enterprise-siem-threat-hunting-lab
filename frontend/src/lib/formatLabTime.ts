export function formatLabTime(iso: string): string {
  const date = iso.slice(0, 16).replace('T', ' ')
  return `${date} UTC`
}
