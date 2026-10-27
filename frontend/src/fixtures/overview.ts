// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
// The numbers live in /fixtures/overview.json so the API and the UI share one copy.
import raw from '../../../fixtures/overview.json'
import type { OverviewData } from '../types/overview.ts'

/**
 * Demo story for the planned MVP chain in docs/ROADMAP.md.
 * Counts below are fixture arithmetic, not lab measurements.
 *
 * alerts = 78 = critical 6 + high 17 + medium 21 + low 34
 * auth failures = 28 = Credential Access
 * tactic, source-IP, and targeted-user counts each sum to 78
 * events ingested (640) includes those 78 alerts
 * 3 active incidents; 2 of them are critical
 * mean time to investigate is null on purpose
 * risk scores are fixture points, not a correlation-engine result
 * monitored endpoints are DC01, WS01, and UBU01
 */
function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0)
}

function assertFixture(data: OverviewData): OverviewData {
  const alerts = sum(
    data.alertsOverTime.map(
      (bucket) => bucket.critical + bucket.high + bucket.medium + bucket.low,
    ),
  )
  const bySeverity = sum(data.alertsBySeverity.map((item) => item.count))
  const byTactic = sum(data.alertsByTactic.map((item) => item.count))
  const byIp = sum(data.topSourceIps.map((item) => item.count))
  const byUser = sum(data.topTargetedUsers.map((item) => item.count))
  const critical = sum(data.alertsOverTime.map((bucket) => bucket.critical))
  const high = sum(data.alertsOverTime.map((bucket) => bucket.high))
  const authFailures = sum(
    data.authFailuresOverTime.map((bucket) => bucket.count),
  )
  const credentialAccess = data.alertsByTactic.find(
    (item) => item.tactic === 'Credential Access',
  )?.count
  const consistent =
    alerts === bySeverity &&
    alerts === byTactic &&
    alerts === byIp &&
    alerts === byUser &&
    data.kpis.criticalAlerts24h === critical &&
    data.kpis.highAlerts24h === high &&
    authFailures === credentialAccess &&
    data.kpis.activeIncidents === data.incidents.length &&
    data.kpis.eventsIngested24h >= alerts &&
    data.kpis.meanTimeToInvestigateMinutes === null

  if (!consistent) {
    throw new Error('Overview fixture counts are not internally consistent')
  }
  return data
}

type OverviewFile = OverviewData & { _notice: string }

const file = raw as OverviewFile

if (!file._notice.startsWith('DEMO DATA')) {
  throw new Error('Overview fixture is missing the DEMO DATA notice')
}

const { _notice, ...data } = file
void _notice

export const overviewFixture: OverviewData = assertFixture(data)
