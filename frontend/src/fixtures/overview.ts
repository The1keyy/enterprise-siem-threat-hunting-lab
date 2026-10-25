// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
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
 * risk scores are fixture points, not a Step 14 result
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

export const overviewFixture: OverviewData = assertFixture({
  demo: true,
  generatedAt: '2026-10-25T16:00:00Z',
  kpis: {
    demo: true,
    activeIncidents: 3,
    criticalAlerts24h: 6,
    highAlerts24h: 17,
    monitoredEndpoints: 3,
    detectionRulesEnabled: 12,
    eventsIngested24h: 640,
    meanTimeToInvestigateMinutes: null,
  },
  alertsOverTime: [
    {
      demo: true,
      bucketStart: '2026-10-24T16:00:00Z',
      label: '16:00',
      critical: 0,
      high: 1,
      medium: 2,
      low: 4,
    },
    {
      demo: true,
      bucketStart: '2026-10-24T19:00:00Z',
      label: '19:00',
      critical: 0,
      high: 2,
      medium: 3,
      low: 5,
    },
    {
      demo: true,
      bucketStart: '2026-10-24T22:00:00Z',
      label: '22:00',
      critical: 1,
      high: 1,
      medium: 2,
      low: 3,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T01:00:00Z',
      label: '01:00',
      critical: 0,
      high: 2,
      medium: 4,
      low: 6,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T04:00:00Z',
      label: '04:00',
      critical: 1,
      high: 3,
      medium: 3,
      low: 4,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T07:00:00Z',
      label: '07:00',
      critical: 2,
      high: 4,
      medium: 2,
      low: 3,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T10:00:00Z',
      label: '10:00',
      critical: 1,
      high: 2,
      medium: 3,
      low: 5,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T13:00:00Z',
      label: '13:00',
      critical: 1,
      high: 2,
      medium: 2,
      low: 4,
    },
  ],
  alertsBySeverity: [
    { demo: true, severity: 'critical', count: 6 },
    { demo: true, severity: 'high', count: 17 },
    { demo: true, severity: 'medium', count: 21 },
    { demo: true, severity: 'low', count: 34 },
  ],
  alertsByTactic: [
    { demo: true, tactic: 'Credential Access', count: 28 },
    { demo: true, tactic: 'Execution', count: 14 },
    { demo: true, tactic: 'Lateral Movement', count: 13 },
    { demo: true, tactic: 'Initial Access', count: 8 },
    { demo: true, tactic: 'Privilege Escalation', count: 6 },
    { demo: true, tactic: 'Persistence', count: 5 },
    { demo: true, tactic: 'Command and Control', count: 4 },
  ],
  authFailuresOverTime: [
    {
      demo: true,
      bucketStart: '2026-10-24T16:00:00Z',
      label: '16:00',
      count: 2,
    },
    {
      demo: true,
      bucketStart: '2026-10-24T19:00:00Z',
      label: '19:00',
      count: 3,
    },
    {
      demo: true,
      bucketStart: '2026-10-24T22:00:00Z',
      label: '22:00',
      count: 2,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T01:00:00Z',
      label: '01:00',
      count: 4,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T04:00:00Z',
      label: '04:00',
      count: 5,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T07:00:00Z',
      label: '07:00',
      count: 6,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T10:00:00Z',
      label: '10:00',
      count: 3,
    },
    {
      demo: true,
      bucketStart: '2026-10-25T13:00:00Z',
      label: '13:00',
      count: 3,
    },
  ],
  topSourceIps: [
    { demo: true, label: '10.10.10.20', count: 34 },
    { demo: true, label: '10.10.10.10', count: 22 },
    { demo: true, label: '10.10.10.30', count: 12 },
    { demo: true, label: '10.10.10.40', count: 10 },
  ],
  topTargetedUsers: [
    { demo: true, label: 'sf-test-alice', count: 30 },
    { demo: true, label: 'sf-test-bob', count: 22 },
    { demo: true, label: 'sf-test-carol', count: 16 },
    { demo: true, label: 'sf-test-dave', count: 10 },
  ],
  topRiskyHosts: [
    { demo: true, name: 'WS01', detail: '10.10.10.20', riskScore: 86 },
    { demo: true, name: 'DC01', detail: '10.10.10.10', riskScore: 74 },
    { demo: true, name: 'UBU01', detail: '10.10.10.30', riskScore: 21 },
  ],
  topRiskyUsers: [
    { demo: true, name: 'sf-test-alice', detail: 'WS01', riskScore: 64 },
    { demo: true, name: 'sf-test-bob', detail: 'DC01', riskScore: 41 },
    { demo: true, name: 'sf-test-carol', detail: 'WS01', riskScore: 22 },
  ],
  incidents: [
    {
      demo: true,
      id: 'INC-0001',
      title: 'Password spray then PowerShell on WS01',
      severity: 'critical',
      status: 'Investigating',
      host: 'WS01',
      user: 'sf-test-alice',
      lastSeen: '2026-10-25T15:40:00Z',
    },
    {
      demo: true,
      id: 'INC-0002',
      title: 'Privileged group change on DC01',
      severity: 'critical',
      status: 'New',
      host: 'DC01',
      user: 'sf-test-bob',
      lastSeen: '2026-10-25T15:12:00Z',
    },
    {
      demo: true,
      id: 'INC-0003',
      title: 'Repeated failed logons against sf-test-carol',
      severity: 'high',
      status: 'New',
      host: 'WS01',
      user: 'sf-test-carol',
      lastSeen: '2026-10-25T14:05:00Z',
    },
  ],
  recentDetections: [
    {
      demo: true,
      id: 'SF-002',
      name: 'Password spray',
      severity: 'critical',
      host: 'WS01',
      time: '2026-10-25T15:36:00Z',
    },
    {
      demo: true,
      id: 'SF-004',
      name: 'Suspicious PowerShell script block',
      severity: 'critical',
      host: 'WS01',
      time: '2026-10-25T15:38:00Z',
    },
    {
      demo: true,
      id: 'SF-007',
      name: 'User added to local Administrators',
      severity: 'high',
      host: 'DC01',
      time: '2026-10-25T15:10:00Z',
    },
    {
      demo: true,
      id: 'SF-010',
      name: 'Inbound RDP logon',
      severity: 'high',
      host: 'DC01',
      time: '2026-10-25T15:18:00Z',
    },
    {
      demo: true,
      id: 'SF-001',
      name: 'Repeated failed logons',
      severity: 'medium',
      host: 'WS01',
      time: '2026-10-25T15:20:00Z',
    },
  ],
  activeTechniques: [
    { demo: true, id: 'T1110.001', name: 'Password Guessing' },
    { demo: true, id: 'T1110.003', name: 'Password Spraying' },
    { demo: true, id: 'T1078', name: 'Valid Accounts' },
    { demo: true, id: 'T1059.001', name: 'PowerShell' },
    { demo: true, id: 'T1105', name: 'Ingress Tool Transfer' },
    { demo: true, id: 'T1098', name: 'Account Manipulation' },
    { demo: true, id: 'T1136.001', name: 'Local Account' },
    { demo: true, id: 'T1021.001', name: 'Remote Desktop Protocol' },
    { demo: true, id: 'T1021.002', name: 'SMB / Windows Admin Shares' },
    { demo: true, id: 'T1021.006', name: 'Windows Remote Management' },
  ],
  health: [
    {
      demo: true,
      name: 'Data ingestion',
      status: 'Healthy',
      lastEvent: '2026-10-25T15:58:00Z',
    },
    {
      demo: true,
      name: 'Agent health',
      status: 'Healthy',
      lastEvent: '2026-10-25T15:57:00Z',
    },
    {
      demo: true,
      name: 'Telemetry status',
      status: 'Healthy',
      lastEvent: '2026-10-25T15:56:00Z',
    },
  ],
})
