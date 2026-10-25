// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
import { technique } from '../lib/techniques.ts'
import type {
  Detection,
  DetectionSeverity,
  TelemetrySource,
} from '../types/detection.ts'

const NOT_WRITTEN = 'Not written yet (Step 10)'

type Draft = {
  id: string
  name: string
  description: string
  severity: DetectionSeverity
  mitre: string[]
  telemetry: TelemetrySource[]
  windowsValidationRequired: boolean
  expectedEvent: string
  testProcedure: string
}

function detection(draft: Draft): Detection {
  return {
    id: draft.id,
    name: draft.name,
    description: draft.description,
    severity: draft.severity,
    mitre: draft.mitre.map((id) => technique(id)),
    telemetry: draft.telemetry,
    wazuhRuleIds: [],
    version: '0.1.0',
    enabled: true,
    status: 'NOT TESTED',
    windowsValidationRequired: draft.windowsValidationRequired,
    falsePositives: 'No lab review yet.',
    tuningNotes: 'No tuning yet. The rule text is not written.',
    testProcedure: draft.testProcedure,
    expectedEvent: draft.expectedEvent,
    expectedAlert: `A Wazuh alert whose description starts with ${draft.id}. Not written yet.`,
    observedResult: 'NOT YET VALIDATED',
    lastTriggered: null,
    alertCount: null,
    wazuhRuleXml: NOT_WRITTEN,
    sigmaYaml: NOT_WRITTEN,
    tuningHistory: [],
    demo: true,
  }
}

const logtest =
  'Replay a labeled synthetic sample with wazuh-logtest in Step 9. This has not been run.'

export const detectionFixtures: readonly Detection[] = [
  detection({
    id: 'SF-001',
    name: 'Repeated failed logons',
    description:
      'Security 4625 repeated against one account. VERIFY Wazuh field names.',
    severity: 'medium',
    mitre: ['T1110.001'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4625',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-002',
    name: 'Password spray',
    description:
      'Security 4625 across many accounts from one source. VERIFY frequency and timeframe.',
    severity: 'critical',
    mitre: ['T1110.003'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4625',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-003',
    name: 'Successful logon after failures',
    description: 'Security 4624 after 4625. VERIFY frequency handling.',
    severity: 'high',
    mitre: ['T1078'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4624 after 4625',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-004',
    name: 'Suspicious PowerShell script block',
    description:
      'PowerShell Operational 4104. Script block logging must be enabled first.',
    severity: 'critical',
    mitre: ['T1059.001'],
    telemetry: ['powershell'],
    windowsValidationRequired: true,
    expectedEvent: 'PowerShell Operational 4104',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-005',
    name: 'Encoded PowerShell process',
    description:
      'Sysmon 1 CommandLine. Security 4688 only if command-line auditing is on. VERIFY 4688 setup.',
    severity: 'critical',
    mitre: ['T1059.001'],
    telemetry: ['sysmon'],
    windowsValidationRequired: true,
    expectedEvent: 'Sysmon 1',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-006',
    name: 'PowerShell download cradle',
    description:
      '4104 plus Sysmon 3 when a connection is logged. Sysmon 3 fields require Windows validation.',
    severity: 'high',
    mitre: ['T1105'],
    telemetry: ['powershell', 'sysmon'],
    windowsValidationRequired: true,
    expectedEvent: 'PowerShell Operational 4104 and Sysmon 3',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-007',
    name: 'User added to local Administrators',
    description: 'Security 4732. VERIFY against a lab event on WS01.',
    severity: 'high',
    mitre: ['T1098'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4732',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-008',
    name: 'User added to a privileged domain group',
    description:
      'Security 4728 for a global group such as Domain Admins. 4756 is universal. VERIFY which event DC01 emits.',
    severity: 'critical',
    mitre: ['T1098'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4728',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-009',
    name: 'New local or domain user',
    description: 'Security 4720.',
    severity: 'low',
    mitre: ['T1136.001'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4720',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-010',
    name: 'Inbound RDP logon',
    description:
      'Security 4624, logon type 10. VERIFY the decoded field name. win.eventdata.logonType is a candidate.',
    severity: 'high',
    mitre: ['T1021.001'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4624 logon type 10',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-011',
    name: 'SMB / admin-share remote logon',
    description:
      'Security 4624, logon type 3. Share detail 5140 or 5145. VERIFY which share event the audit policy produces.',
    severity: 'high',
    mitre: ['T1021.002'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4624 logon type 3',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-012',
    name: 'WinRM / PowerShell remoting',
    description:
      'Security 4624 type 3. WinRM Operational event IDs are VERIFY and are not assumed.',
    severity: 'high',
    mitre: ['T1021.006'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4624 logon type 3',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-013',
    name: 'Linux SSH failure burst',
    description:
      'sshd failed-password lines. VERIFY the Ubuntu 24.04 auth log path.',
    severity: 'medium',
    mitre: ['T1110.001'],
    telemetry: ['linux_auth'],
    windowsValidationRequired: false,
    expectedEvent: 'sshd failed password',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-014',
    name: 'Linux SSH success after failures',
    description: 'sshd accepted-password line.',
    severity: 'medium',
    mitre: ['T1078'],
    telemetry: ['linux_auth'],
    windowsValidationRequired: false,
    expectedEvent: 'sshd accepted password',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-015',
    name: 'Suspicious Linux command execution',
    description: 'auditd EXECVE or SYSCALL. VERIFY key names.',
    severity: 'low',
    mitre: ['T1059.004'],
    telemetry: ['auditd'],
    windowsValidationRequired: false,
    expectedEvent: 'auditd EXECVE',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-016',
    name: 'LSASS memory access',
    description: 'Sysmon 10. Requires Windows validation.',
    severity: 'critical',
    mitre: ['T1003.001'],
    telemetry: ['sysmon'],
    windowsValidationRequired: true,
    expectedEvent: 'Sysmon 10',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-017',
    name: 'Scheduled task created',
    description: 'Security 4698. Requires Windows validation.',
    severity: 'medium',
    mitre: ['T1053.005'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 4698',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-018',
    name: 'Security log cleared',
    description: 'Security 1102. Requires Windows validation.',
    severity: 'high',
    mitre: ['T1070.001'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'Security 1102',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-019',
    name: 'New service installed',
    description:
      'System 7045. VERIFY the channel and Wazuh decoder. Requires Windows validation.',
    severity: 'high',
    mitre: ['T1543.003'],
    telemetry: ['windows_security'],
    windowsValidationRequired: true,
    expectedEvent: 'System 7045',
    testProcedure: logtest,
  }),
  detection({
    id: 'SF-020',
    name: 'Suricata alert on lab traffic',
    description:
      'eve.json alert record. VERIFY the schema for the Suricata version that gets installed. SURI01 stays off until then.',
    severity: 'medium',
    mitre: ['T1071'],
    telemetry: ['suricata'],
    windowsValidationRequired: false,
    expectedEvent: 'Suricata eve.json alert',
    testProcedure: logtest,
  }),
]

const ids = detectionFixtures.map((item) => item.id)
if (
  ids.length !== 20 ||
  ids.some((id, index) => id !== `SF-${String(index + 1).padStart(3, '0')}`)
) {
  throw new Error('Detection fixtures must be SF-001 through SF-020')
}
if (detectionFixtures.some((item) => item.status !== 'NOT TESTED')) {
  throw new Error('Every detection fixture must be NOT TESTED')
}
