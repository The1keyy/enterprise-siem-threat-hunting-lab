// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
// Hunt drafts live in /fixtures/hunts.json. Queries are not lab results.
import raw from '../../../fixtures/hunts.json'
import type { Hunt } from '../types/hunt.ts'

type HuntFile = {
  _notice: string
  hunts: Hunt[]
}

const file = raw as HuntFile

if (!file._notice.startsWith('DEMO DATA')) {
  throw new Error('Hunt fixtures are missing the DEMO DATA notice')
}

export const huntFixtures: readonly Hunt[] = file.hunts
