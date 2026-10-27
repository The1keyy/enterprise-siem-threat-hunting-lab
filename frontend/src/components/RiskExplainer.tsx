import type { RiskLine } from '../types/entity.ts'

export function RiskExplainer({ lines }: { lines: readonly RiskLine[] }) {
  const total = lines.reduce((sum, line) => sum + line.decayed, 0)
  return (
    <details className="rounded-card border border-border bg-surface p-4">
      <summary className="cursor-pointer text-sm font-medium text-text">
        How risk is calculated
      </summary>
      <p className="mt-2 text-sm text-text-muted">
        The entity score sums each incident&apos;s counted subtotal, then halves
        that weight every 24 hours after the incident&apos;s last alert. The
        asset multiplier is not applied again.
      </p>
      {lines.length === 0 ? (
        <p className="mt-2 text-sm text-text-muted">No data yet.</p>
      ) : (
        <table className="mt-3 w-full text-left text-sm">
          <thead className="text-xs text-text-muted">
            <tr>
              <th className="py-1 font-medium">Incident</th>
              <th className="py-1 font-medium">Subtotal</th>
              <th className="py-1 font-medium">Multiplier</th>
              <th className="py-1 text-right font-medium">Decayed</th>
            </tr>
          </thead>
          <tbody>
            {lines.map((line) => (
              <tr key={line.incidentId} className="border-t border-border">
                <td className="py-1 text-text">
                  {line.incidentId} · {line.assetType.replaceAll('_', ' ')}
                </td>
                <td className="py-1">{line.subtotal}</td>
                <td className="py-1">× {line.multiplier}</td>
                <td className="py-1 text-right">{line.decayed}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="mt-2 text-sm text-text">Score {total}</p>
    </details>
  )
}
