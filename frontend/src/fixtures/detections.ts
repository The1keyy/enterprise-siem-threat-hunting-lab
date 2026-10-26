// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
// Detection metadata lives in /fixtures/detections.json.
// Written rules carry their real status. Unwritten rows stay NOT TESTED.
import raw from '../../../fixtures/detections.json'
import type { Detection } from '../types/detection.ts'

type DetectionFile = {
  _notice: string
  detections: Detection[]
}

const file = raw as DetectionFile

if (!file._notice.startsWith('DEMO DATA')) {
  throw new Error('Detection fixtures are missing the DEMO DATA notice')
}

export const detectionFixtures: readonly Detection[] = file.detections
