import type { MitreTechnique } from '../types/incident.ts'

export const TACTIC_COLUMNS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
] as const

export type TacticColumn = (typeof TACTIC_COLUMNS)[number]

const TECHNIQUES: Record<string, MitreTechnique> = {
  T1078: {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Initial Access',
  },
  'T1059.001': {
    id: 'T1059.001',
    name: 'PowerShell',
    tactic: 'Execution',
  },
  'T1059.004': {
    id: 'T1059.004',
    name: 'Unix Shell',
    tactic: 'Execution',
  },
  'T1136.001': {
    id: 'T1136.001',
    name: 'Local Account',
    tactic: 'Persistence',
  },
  T1098: {
    id: 'T1098',
    name: 'Account Manipulation',
    tactic: 'Persistence',
  },
  'T1053.005': {
    id: 'T1053.005',
    name: 'Scheduled Task',
    tactic: 'Persistence',
  },
  'T1543.003': {
    id: 'T1543.003',
    name: 'Windows Service',
    tactic: 'Persistence',
  },
  'T1070.001': {
    id: 'T1070.001',
    name: 'Clear Windows Event Logs',
    tactic: 'Defense Evasion',
  },
  'T1110.001': {
    id: 'T1110.001',
    name: 'Password Guessing',
    tactic: 'Credential Access',
  },
  'T1110.003': {
    id: 'T1110.003',
    name: 'Password Spraying',
    tactic: 'Credential Access',
  },
  'T1003.001': {
    id: 'T1003.001',
    name: 'LSASS Memory',
    tactic: 'Credential Access',
  },
  'T1021.001': {
    id: 'T1021.001',
    name: 'Remote Desktop Protocol',
    tactic: 'Lateral Movement',
  },
  'T1021.002': {
    id: 'T1021.002',
    name: 'SMB / Windows Admin Shares',
    tactic: 'Lateral Movement',
  },
  'T1021.006': {
    id: 'T1021.006',
    name: 'Windows Remote Management',
    tactic: 'Lateral Movement',
  },
  T1105: {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
  },
  T1071: {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
  },
}

export function technique(id: string): MitreTechnique {
  const found = TECHNIQUES[id]
  if (!found) {
    throw new Error(`Technique ${id} is not in the roadmap map`)
  }
  return found
}

export function techniquesForTactic(tactic: TacticColumn): MitreTechnique[] {
  return Object.values(TECHNIQUES)
    .filter((item) => item.tactic === tactic)
    .sort((left, right) => left.id.localeCompare(right.id))
}
