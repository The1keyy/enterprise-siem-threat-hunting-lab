import { useMemo } from 'react'
import { getDataMode } from '../services/config.ts'
import type { DataMode } from '../types/domain.ts'

export function useDataMode(): DataMode {
  return useMemo(() => getDataMode(), [])
}
