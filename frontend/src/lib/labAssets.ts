import { ASSET_MULTIPLIERS } from './risk.ts'
import type { RiskAssetType, RiskMultiplier } from '../types/incident.ts'

export type LabAsset = {
  name: string
  ip: string
  os: string
  assetType: RiskAssetType
  multiplier: RiskMultiplier
}

/** Addresses from architecture/ARCHITECTURE.md. OS editions marked VERIFY are not confirmed. */
export const LAB_ASSETS: readonly LabAsset[] = [
  {
    name: 'DC01',
    ip: '10.10.10.10',
    os: 'Windows Server evaluation (VERIFY: 2022 or 2025)',
    assetType: 'domain_controller',
    multiplier: ASSET_MULTIPLIERS.domain_controller,
  },
  {
    name: 'WS01',
    ip: '10.10.10.20',
    os: 'Windows 11',
    assetType: 'workstation',
    multiplier: ASSET_MULTIPLIERS.workstation,
  },
  {
    name: 'UBU01',
    ip: '10.10.10.30',
    os: 'Ubuntu Server 24.04',
    assetType: 'server',
    multiplier: ASSET_MULTIPLIERS.server,
  },
  {
    name: 'WAZUH01',
    ip: '10.10.10.40',
    os: 'Ubuntu Server 24.04',
    assetType: 'server',
    multiplier: ASSET_MULTIPLIERS.server,
  },
  {
    name: 'SURI01',
    ip: '10.10.10.50',
    os: 'Ubuntu Server 24.04',
    assetType: 'server',
    multiplier: ASSET_MULTIPLIERS.server,
  },
]

export function labAsset(name: string): LabAsset | null {
  return LAB_ASSETS.find((item) => item.name === name) ?? null
}
