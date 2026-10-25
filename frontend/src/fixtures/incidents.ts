// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
import { finalRiskScore, severityBandFor } from '../lib/risk.ts'
import type { IncidentStatus, Severity } from '../types/domain.ts'
import type {
  Disposition,
  Entities,
  IncidentDetail,
  MitreTechnique,
  Note,
  RiskAssetType,
  RiskItem,
  RiskMultiplier,
  TimelineEvent,
} from '../types/incident.ts'

/**
 * Story weights from the Step 5 brief. Other weights exist only so the
 * non-story rows have a breakdown. Step 14 replaces every weight.
 * VERIFY: Wazuh 4.14.9 rule.id, agent.id, decoder.name, and data.win.eventdata.*
 * (and Linux data.srcip / auditd keys). Those ids are the literal "VERIFY"
 * inside the raw JSON. Event data keys are candidates, not confirmed fields.
 */
const FAILED_AUTH = 15
const SUCCESS_AFTER_FAILURES = 25
const ENCODED_POWERSHELL = 30
const PRIVILEGED_GROUP = 35
const REMOTE_CONNECTION = 20
const NEW_ACCOUNT = 10
const SUSPICIOUS_COMMAND = 20
const SCHEDULED_TASK = 15

type HostName = 'DC01' | 'WS01' | 'UBU01' | 'WAZUH01'

const HOST_IP: Record<HostName, string> = {
  DC01: '10.10.10.10',
  WS01: '10.10.10.20',
  UBU01: '10.10.10.30',
  WAZUH01: '10.10.10.40',
}

function windowsAlert(input: {
  time: string
  description: string
  level: number
  host: HostName
  eventId: string
  channel: string
  groups: string[]
  eventData: Record<string, string>
}): Record<string, unknown> {
  return {
    timestamp: input.time,
    rule: {
      id: 'VERIFY',
      level: input.level,
      description: input.description,
      groups: input.groups,
    },
    agent: {
      id: 'VERIFY',
      name: input.host,
      ip: HOST_IP[input.host],
    },
    manager: { name: 'WAZUH01' },
    decoder: { name: 'windows_eventchannel' },
    data: {
      win: {
        system: {
          eventID: input.eventId,
          channel: input.channel,
          computer: `${input.host}.sentinelforge.lab`,
        },
        eventdata: input.eventData,
      },
    },
  }
}

function linuxAlert(input: {
  time: string
  description: string
  level: number
  host: HostName
  decoder: string
  groups: string[]
  data: Record<string, unknown>
  fullLog: string
}): Record<string, unknown> {
  return {
    timestamp: input.time,
    rule: {
      id: 'VERIFY',
      level: input.level,
      description: input.description,
      groups: input.groups,
    },
    agent: {
      id: 'VERIFY',
      name: input.host,
      ip: HOST_IP[input.host],
    },
    manager: { name: 'WAZUH01' },
    decoder: { name: input.decoder },
    data: input.data,
    full_log: input.fullLog,
  }
}

function technique(id: string, name: string, tactic: string): MitreTechnique {
  return { id, name, tactic }
}

type Draft = {
  id: string
  title: string
  severity: Severity
  status: IncidentStatus
  owner: string
  users: string[]
  hosts: string[]
  mitre: MitreTechnique[]
  timeline: TimelineEvent[]
  entities: Entities
  riskItems: RiskItem[]
  assetType: RiskAssetType
  multiplier: RiskMultiplier
  notes?: Note[]
  disposition?: Disposition
  summary?: string
  recommendedContainment: string[]
}

function buildIncident(draft: Draft): IncidentDetail {
  const subtotal = draft.riskItems.reduce((sum, item) => sum + item.points, 0)
  const final = finalRiskScore(subtotal, draft.multiplier)
  const first = draft.timeline[0]
  const last = draft.timeline[draft.timeline.length - 1]
  if (!first || !last) {
    throw new Error(`Incident ${draft.id} needs a timeline`)
  }
  const detail: IncidentDetail = {
    id: draft.id,
    title: draft.title,
    severity: draft.severity,
    riskScore: final,
    status: draft.status,
    owner: draft.owner,
    users: draft.users,
    hosts: draft.hosts,
    mitre: draft.mitre,
    firstSeen: first.time,
    lastSeen: last.time,
    demo: true,
    timeline: draft.timeline,
    entities: draft.entities,
    risk: {
      items: draft.riskItems,
      subtotal,
      assetType: draft.assetType,
      multiplier: draft.multiplier,
      final,
      severityBand: severityBandFor(final),
    },
    notes: draft.notes ?? [],
    disposition: draft.disposition ?? 'Undetermined',
    summary: draft.summary ?? '',
    recommendedContainment: draft.recommendedContainment,
    audit: [],
  }
  if (detail.risk.final !== Math.round(subtotal * draft.multiplier)) {
    throw new Error(`Incident ${draft.id} final score drifted from the math`)
  }
  return detail
}

const alice = 'sf-test-alice'
const bob = 'sf-test-bob'
const carol = 'sf-test-carol'
const dave = 'sf-test-dave'

const story: IncidentDetail = buildIncident({
  id: 'INC-0001',
  title: 'Password spray then PowerShell on WS01',
  severity: 'critical',
  status: 'Investigating',
  owner: 'Analyst',
  users: [alice],
  hosts: ['WS01'],
  mitre: [
    technique('T1110.003', 'Password Spraying', 'Credential Access'),
    technique('T1078', 'Valid Accounts', 'Initial Access'),
    technique('T1059.001', 'PowerShell', 'Execution'),
    technique('T1098', 'Account Manipulation', 'Persistence'),
    technique('T1021.002', 'SMB / Windows Admin Shares', 'Lateral Movement'),
  ],
  timeline: [
    {
      time: '2026-10-25T15:20:00Z',
      title: 'Failed-auth burst',
      source: 'windows_security',
      host: 'WS01',
      user: alice,
      eventId: '4625',
      ruleId: 'SF-002',
      severity: 'critical',
      raw: windowsAlert({
        time: '2026-10-25T15:20:00.000Z',
        description: 'Password spray after repeated failed logons',
        level: 10,
        host: 'WS01',
        eventId: '4625',
        channel: 'Security',
        groups: ['windows', 'authentication_failed'],
        eventData: {
          targetUserName: alice,
          ipAddress: '10.10.10.20',
          logonType: '3',
          workstationName: 'WS01',
          status: '0xc000006d',
        },
      }),
    },
    {
      time: '2026-10-25T15:25:00Z',
      title: 'Successful login after failures',
      source: 'windows_security',
      host: 'WS01',
      user: alice,
      eventId: '4624',
      ruleId: 'SF-003',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T15:25:00.000Z',
        description: 'Successful logon after failures',
        level: 12,
        host: 'WS01',
        eventId: '4624',
        channel: 'Security',
        groups: ['windows', 'authentication_success'],
        eventData: {
          targetUserName: alice,
          ipAddress: '10.10.10.20',
          logonType: '3',
          workstationName: 'WS01',
        },
      }),
    },
    {
      time: '2026-10-25T15:30:00Z',
      title: 'Suspicious encoded PowerShell',
      source: 'sysmon',
      host: 'WS01',
      user: alice,
      eventId: '1',
      ruleId: 'SF-005',
      severity: 'critical',
      raw: windowsAlert({
        time: '2026-10-25T15:30:00.000Z',
        description: 'Encoded PowerShell process',
        level: 12,
        host: 'WS01',
        eventId: '1',
        channel: 'Microsoft-Windows-Sysmon/Operational',
        groups: ['windows', 'sysmon', 'sysmon_eid1_detections'],
        eventData: {
          image:
            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          commandLine: 'powershell.exe -NoP -NonI -EncodedCommand ZABlAG0AbwA=',
          parentImage: 'C:\\Windows\\System32\\cmd.exe',
          parentCommandLine: 'cmd.exe',
          user: alice,
        },
      }),
    },
    {
      time: '2026-10-25T15:35:00Z',
      title: 'User added to privileged group',
      source: 'windows_security',
      host: 'WS01',
      user: alice,
      eventId: '4732',
      ruleId: 'SF-007',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T15:35:00.000Z',
        description: 'User added to local Administrators',
        level: 12,
        host: 'WS01',
        eventId: '4732',
        channel: 'Security',
        groups: ['windows', 'account_changed'],
        eventData: {
          memberName: alice,
          targetUserName: 'Administrators',
          subjectUserName: alice,
        },
      }),
    },
    {
      time: '2026-10-25T15:40:00Z',
      title: 'Remote connection RDP/SMB',
      source: 'windows_security',
      host: 'WS01',
      user: alice,
      eventId: '4624',
      ruleId: 'SF-011',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T15:40:00.000Z',
        description: 'SMB admin-share remote logon',
        level: 10,
        host: 'WS01',
        eventId: '4624',
        channel: 'Security',
        groups: ['windows', 'authentication_success'],
        eventData: {
          targetUserName: alice,
          ipAddress: '10.10.10.20',
          logonType: '3',
          workstationName: 'WS01',
          shareName: '\\\\DC01\\ADMIN$',
        },
      }),
    },
  ],
  entities: {
    users: [alice],
    hosts: ['WS01'],
    srcIps: ['10.10.10.20'],
    dstIps: ['10.10.10.10'],
    processes: ['powershell.exe'],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    { event: 'Failed-auth burst', ruleId: 'SF-002', points: FAILED_AUTH },
    {
      event: 'Successful login after failures',
      ruleId: 'SF-003',
      points: SUCCESS_AFTER_FAILURES,
    },
    {
      event: 'Suspicious encoded PowerShell',
      ruleId: 'SF-005',
      points: ENCODED_POWERSHELL,
    },
    {
      event: 'User added to privileged group',
      ruleId: 'SF-007',
      points: PRIVILEGED_GROUP,
    },
    {
      event: 'Remote connection RDP/SMB',
      ruleId: 'SF-011',
      points: REMOTE_CONNECTION,
    },
  ],
  assetType: 'workstation',
  multiplier: 1,
  notes: [
    {
      id: 'NOTE-0001',
      author: 'Analyst',
      time: '2026-10-25T15:42:00Z',
      text: 'DEMO DATA. Timeline follows the planned MVP story. Not a lab finding.',
    },
  ],
  summary: '',
  recommendedContainment: [
    'Snapshot WS01 before any lab change',
    'Isolate WS01 from the lab network',
    'Disable sf-test-alice',
    'Block 10.10.10.20 on the lab segment',
  ],
})

const domainAdmins: IncidentDetail = buildIncident({
  id: 'INC-0002',
  title: 'Privileged group change on DC01',
  severity: 'critical',
  status: 'New',
  owner: 'Unassigned',
  users: [bob],
  hosts: ['DC01'],
  mitre: [
    technique('T1110.001', 'Password Guessing', 'Credential Access'),
    technique('T1098', 'Account Manipulation', 'Persistence'),
    technique('T1021.001', 'Remote Desktop Protocol', 'Lateral Movement'),
  ],
  timeline: [
    {
      time: '2026-10-25T15:02:00Z',
      title: 'Failed-auth burst',
      source: 'windows_security',
      host: 'DC01',
      user: bob,
      eventId: '4625',
      ruleId: 'SF-001',
      severity: 'medium',
      raw: windowsAlert({
        time: '2026-10-25T15:02:00.000Z',
        description: 'Repeated failed logons',
        level: 8,
        host: 'DC01',
        eventId: '4625',
        channel: 'Security',
        groups: ['windows', 'authentication_failed'],
        eventData: {
          targetUserName: bob,
          ipAddress: '10.10.10.20',
          logonType: '3',
          workstationName: 'WS01',
        },
      }),
    },
    {
      time: '2026-10-25T15:08:00Z',
      title: 'User added to privileged group',
      source: 'windows_security',
      host: 'DC01',
      user: bob,
      eventId: '4728',
      ruleId: 'SF-008',
      severity: 'critical',
      raw: windowsAlert({
        time: '2026-10-25T15:08:00.000Z',
        description: 'User added to a privileged domain group',
        level: 14,
        host: 'DC01',
        eventId: '4728',
        channel: 'Security',
        groups: ['windows', 'account_changed'],
        eventData: {
          memberName: bob,
          targetUserName: 'Domain Admins',
          subjectUserName: alice,
        },
      }),
    },
    {
      time: '2026-10-25T15:12:00Z',
      title: 'Inbound RDP logon',
      source: 'windows_security',
      host: 'DC01',
      user: bob,
      eventId: '4624',
      ruleId: 'SF-010',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T15:12:00.000Z',
        description: 'Inbound RDP logon',
        level: 10,
        host: 'DC01',
        eventId: '4624',
        channel: 'Security',
        groups: ['windows', 'authentication_success'],
        eventData: {
          targetUserName: bob,
          ipAddress: '10.10.10.20',
          logonType: '10',
          workstationName: 'WS01',
        },
      }),
    },
  ],
  entities: {
    users: [bob, alice],
    hosts: ['DC01', 'WS01'],
    srcIps: ['10.10.10.20'],
    dstIps: ['10.10.10.10'],
    processes: [],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    { event: 'Failed-auth burst', ruleId: 'SF-001', points: FAILED_AUTH },
    {
      event: 'User added to privileged group',
      ruleId: 'SF-008',
      points: PRIVILEGED_GROUP,
    },
    {
      event: 'Remote connection RDP/SMB',
      ruleId: 'SF-010',
      points: REMOTE_CONNECTION,
    },
  ],
  assetType: 'domain_controller',
  multiplier: 1.7,
  recommendedContainment: [
    'Snapshot DC01 before any lab change',
    'Disable sf-test-bob',
    'Review Domain Admins membership',
  ],
})

const carolFailures: IncidentDetail = buildIncident({
  id: 'INC-0003',
  title: 'Repeated failed logons against sf-test-carol',
  severity: 'high',
  status: 'New',
  owner: 'Unassigned',
  users: [carol],
  hosts: ['WS01'],
  mitre: [technique('T1110.001', 'Password Guessing', 'Credential Access')],
  timeline: [
    {
      time: '2026-10-25T14:05:00Z',
      title: 'Failed-auth burst',
      source: 'windows_security',
      host: 'WS01',
      user: carol,
      eventId: '4625',
      ruleId: 'SF-001',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T14:05:00.000Z',
        description: 'Repeated failed logons',
        level: 8,
        host: 'WS01',
        eventId: '4625',
        channel: 'Security',
        groups: ['windows', 'authentication_failed'],
        eventData: {
          targetUserName: carol,
          ipAddress: '10.10.10.30',
          logonType: '3',
          workstationName: 'UBU01',
        },
      }),
    },
  ],
  entities: {
    users: [carol],
    hosts: ['WS01'],
    srcIps: ['10.10.10.30'],
    dstIps: ['10.10.10.20'],
    processes: [],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    { event: 'Failed-auth burst', ruleId: 'SF-001', points: FAILED_AUTH },
  ],
  assetType: 'workstation',
  multiplier: 1,
  recommendedContainment: [
    'Confirm sf-test-carol still uses a lab-only password',
  ],
})

const ssh: IncidentDetail = buildIncident({
  id: 'INC-0004',
  title: 'SSH success after failures on UBU01',
  severity: 'medium',
  status: 'Contained',
  owner: 'Analyst',
  users: [dave],
  hosts: ['UBU01'],
  mitre: [
    technique('T1110.001', 'Password Guessing', 'Credential Access'),
    technique('T1078', 'Valid Accounts', 'Initial Access'),
  ],
  timeline: [
    {
      time: '2026-10-25T13:10:00Z',
      title: 'Failed-auth burst',
      source: 'linux_auth',
      host: 'UBU01',
      user: dave,
      eventId: 'sshd-failed',
      ruleId: 'SF-013',
      severity: 'medium',
      raw: linuxAlert({
        time: '2026-10-25T13:10:00.000Z',
        description: 'Linux SSH failure burst',
        level: 8,
        host: 'UBU01',
        decoder: 'sshd',
        groups: ['syslog', 'sshd', 'authentication_failed'],
        data: { srcip: '10.10.10.20', dstuser: dave },
        fullLog: `sshd[2412]: Failed password for ${dave} from 10.10.10.20 port 51224 ssh2`,
      }),
    },
    {
      time: '2026-10-25T13:16:00Z',
      title: 'Successful login after failures',
      source: 'linux_auth',
      host: 'UBU01',
      user: dave,
      eventId: 'sshd-accepted',
      ruleId: 'SF-014',
      severity: 'medium',
      raw: linuxAlert({
        time: '2026-10-25T13:16:00.000Z',
        description: 'Linux SSH success after failures',
        level: 10,
        host: 'UBU01',
        decoder: 'sshd',
        groups: ['syslog', 'sshd', 'authentication_success'],
        data: { srcip: '10.10.10.20', dstuser: dave },
        fullLog: `sshd[2412]: Accepted password for ${dave} from 10.10.10.20 port 51224 ssh2`,
      }),
    },
  ],
  entities: {
    users: [dave],
    hosts: ['UBU01'],
    srcIps: ['10.10.10.20'],
    dstIps: ['10.10.10.30'],
    processes: ['sshd'],
    domains: [],
    hashes: [],
  },
  riskItems: [
    { event: 'Failed-auth burst', ruleId: 'SF-013', points: FAILED_AUTH },
    {
      event: 'Successful login after failures',
      ruleId: 'SF-014',
      points: SUCCESS_AFTER_FAILURES,
    },
  ],
  assetType: 'server',
  multiplier: 1.3,
  recommendedContainment: [
    'Disable sf-test-dave on UBU01',
    'Block 10.10.10.20',
  ],
})

const newUser: IncidentDetail = buildIncident({
  id: 'INC-0005',
  title: 'New local account on WS01',
  severity: 'low',
  status: 'Resolved',
  owner: 'Analyst',
  users: [alice],
  hosts: ['WS01'],
  mitre: [technique('T1136.001', 'Local Account', 'Persistence')],
  timeline: [
    {
      time: '2026-10-25T12:40:00Z',
      title: 'New local user created',
      source: 'windows_security',
      host: 'WS01',
      user: alice,
      eventId: '4720',
      ruleId: 'SF-009',
      severity: 'low',
      raw: windowsAlert({
        time: '2026-10-25T12:40:00.000Z',
        description: 'New local user',
        level: 6,
        host: 'WS01',
        eventId: '4720',
        channel: 'Security',
        groups: ['windows', 'adduser'],
        eventData: {
          targetUserName: 'sf-test-extra',
          subjectUserName: alice,
        },
      }),
    },
  ],
  entities: {
    users: [alice, 'sf-test-extra'],
    hosts: ['WS01'],
    srcIps: ['10.10.10.20'],
    dstIps: [],
    processes: [],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    { event: 'New local user created', ruleId: 'SF-009', points: NEW_ACCOUNT },
  ],
  assetType: 'workstation',
  multiplier: 1,
  recommendedContainment: ['Remove sf-test-extra if the lab account is unused'],
})

const falsePositive: IncidentDetail = buildIncident({
  id: 'INC-0006',
  title: 'Suspicious command on UBU01',
  severity: 'low',
  status: 'False Positive',
  owner: 'Analyst',
  users: [dave],
  hosts: ['UBU01'],
  mitre: [technique('T1059.004', 'Unix Shell', 'Execution')],
  timeline: [
    {
      time: '2026-10-25T11:15:00Z',
      title: 'Suspicious Linux command',
      source: 'auditd',
      host: 'UBU01',
      user: dave,
      eventId: 'EXECVE',
      ruleId: 'SF-015',
      severity: 'low',
      raw: linuxAlert({
        time: '2026-10-25T11:15:00.000Z',
        description: 'Suspicious Linux command execution',
        level: 6,
        host: 'UBU01',
        decoder: 'auditd',
        groups: ['audit', 'auditd'],
        data: {
          audit: {
            exe: '/usr/bin/curl',
            command: 'curl http://10.10.10.40/demo',
          },
        },
        fullLog:
          'type=EXECVE msg=audit(synthetic): argc=2 a0="curl" a1="http://10.10.10.40/demo"',
      }),
    },
  ],
  entities: {
    users: [dave],
    hosts: ['UBU01'],
    srcIps: ['10.10.10.30'],
    dstIps: ['10.10.10.40'],
    processes: ['curl'],
    domains: [],
    hashes: [],
  },
  riskItems: [
    {
      event: 'Suspicious Linux command',
      ruleId: 'SF-015',
      points: SUSPICIOUS_COMMAND,
    },
  ],
  assetType: 'server',
  multiplier: 1.3,
  disposition: 'False positive',
  summary: 'DEMO DATA. Lab health check, not an intrusion.',
  recommendedContainment: ['No containment. Recorded as a false positive.'],
})

const winrm: IncidentDetail = buildIncident({
  id: 'INC-0007',
  title: 'WinRM session from WS01 to WAZUH01',
  severity: 'high',
  status: 'Investigating',
  owner: 'Analyst',
  users: [bob],
  hosts: ['WAZUH01', 'WS01'],
  mitre: [
    technique('T1059.001', 'PowerShell', 'Execution'),
    technique('T1021.006', 'Windows Remote Management', 'Lateral Movement'),
  ],
  timeline: [
    {
      time: '2026-10-25T16:05:00Z',
      title: 'Suspicious encoded PowerShell',
      source: 'powershell',
      host: 'WS01',
      user: bob,
      eventId: '4104',
      ruleId: 'SF-005',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T16:05:00.000Z',
        description: 'Encoded PowerShell process',
        level: 12,
        host: 'WS01',
        eventId: '4104',
        channel: 'Microsoft-Windows-PowerShell/Operational',
        groups: ['windows', 'powershell'],
        eventData: {
          image:
            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          commandLine: 'powershell.exe -NoP -NonI -EncodedCommand ZABlAG0AbwA=',
          parentImage: 'C:\\Windows\\explorer.exe',
          user: bob,
        },
      }),
    },
    {
      time: '2026-10-25T16:09:00Z',
      title: 'WinRM remote connection',
      source: 'windows_security',
      host: 'WAZUH01',
      user: bob,
      eventId: '4624',
      ruleId: 'SF-012',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T16:09:00.000Z',
        description: 'WinRM / PowerShell remoting',
        level: 10,
        host: 'WAZUH01',
        eventId: '4624',
        channel: 'Security',
        groups: ['windows', 'authentication_success'],
        eventData: {
          targetUserName: bob,
          ipAddress: '10.10.10.20',
          logonType: '3',
          workstationName: 'WS01',
        },
      }),
    },
  ],
  entities: {
    users: [bob],
    hosts: ['WAZUH01', 'WS01'],
    srcIps: ['10.10.10.20'],
    dstIps: ['10.10.10.40'],
    processes: ['powershell.exe'],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    {
      event: 'Suspicious encoded PowerShell',
      ruleId: 'SF-005',
      points: ENCODED_POWERSHELL,
    },
    {
      event: 'Remote connection RDP/SMB',
      ruleId: 'SF-012',
      points: REMOTE_CONNECTION,
    },
  ],
  assetType: 'server',
  multiplier: 1.3,
  recommendedContainment: [
    'Snapshot WAZUH01 before any lab change',
    'Disable sf-test-bob',
  ],
})

const scheduled: IncidentDetail = buildIncident({
  id: 'INC-0008',
  title: 'Scheduled task created on WS01',
  severity: 'info',
  status: 'New',
  owner: 'Unassigned',
  users: [carol],
  hosts: ['WS01'],
  mitre: [technique('T1053.005', 'Scheduled Task', 'Persistence')],
  timeline: [
    {
      time: '2026-10-25T10:22:00Z',
      title: 'Scheduled task created',
      source: 'windows_security',
      host: 'WS01',
      user: carol,
      eventId: '4698',
      ruleId: 'SF-017',
      severity: 'info',
      raw: windowsAlert({
        time: '2026-10-25T10:22:00.000Z',
        description: 'Scheduled task created',
        level: 5,
        host: 'WS01',
        eventId: '4698',
        channel: 'Security',
        groups: ['windows', 'policy_changed'],
        eventData: {
          subjectUserName: carol,
          taskName: '\\SentinelForge\\DemoTask',
        },
      }),
    },
  ],
  entities: {
    users: [carol],
    hosts: ['WS01'],
    srcIps: [],
    dstIps: ['10.10.10.20'],
    processes: [],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    {
      event: 'Scheduled task created',
      ruleId: 'SF-017',
      points: SCHEDULED_TASK,
    },
  ],
  assetType: 'workstation',
  multiplier: 1,
  recommendedContainment: [
    'Remove \\SentinelForge\\DemoTask if it is not part of the lab',
  ],
})

const smb: IncidentDetail = buildIncident({
  id: 'INC-0009',
  title: 'SMB admin-share logon from WS01',
  severity: 'high',
  status: 'New',
  owner: 'Unassigned',
  users: [alice],
  hosts: ['WS01'],
  mitre: [
    technique('T1021.002', 'SMB / Windows Admin Shares', 'Lateral Movement'),
  ],
  timeline: [
    {
      time: '2026-10-25T09:48:00Z',
      title: 'Remote connection RDP/SMB',
      source: 'windows_security',
      host: 'WS01',
      user: alice,
      eventId: '4624',
      ruleId: 'SF-011',
      severity: 'high',
      raw: windowsAlert({
        time: '2026-10-25T09:48:00.000Z',
        description: 'SMB admin-share remote logon',
        level: 8,
        host: 'WS01',
        eventId: '4624',
        channel: 'Security',
        groups: ['windows', 'authentication_success'],
        eventData: {
          targetUserName: alice,
          ipAddress: '10.10.10.20',
          logonType: '3',
          workstationName: 'WS01',
          shareName: '\\\\DC01\\C$',
        },
      }),
    },
  ],
  entities: {
    users: [alice],
    hosts: ['WS01', 'DC01'],
    srcIps: ['10.10.10.20'],
    dstIps: ['10.10.10.10'],
    processes: [],
    domains: ['sentinelforge.lab'],
    hashes: [],
  },
  riskItems: [
    {
      event: 'Remote connection RDP/SMB',
      ruleId: 'SF-011',
      points: REMOTE_CONNECTION,
    },
  ],
  assetType: 'workstation',
  multiplier: 1,
  recommendedContainment: ['Confirm the admin share session was a lab test'],
})

export const incidentFixtures: readonly IncidentDetail[] = [
  story,
  domainAdmins,
  carolFailures,
  ssh,
  newUser,
  falsePositive,
  winrm,
  scheduled,
  smb,
]

const storyRisk = story.risk
if (
  storyRisk.subtotal !== 125 ||
  storyRisk.multiplier !== 1 ||
  storyRisk.final !== 125
) {
  throw new Error('INC-0001 must be 125 × 1.0 workstation = 125')
}

const dcRisk = domainAdmins.risk
if (
  dcRisk.subtotal !== 70 ||
  dcRisk.multiplier !== 1.7 ||
  dcRisk.assetType !== 'domain_controller' ||
  dcRisk.final !== Math.round(70 * 1.7)
) {
  throw new Error('INC-0002 must show the 1.7 domain controller multiplier')
}
