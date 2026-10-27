import { access } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const frontendDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const repoFixtures = path.resolve(frontendDir, '../fixtures')
const required = [
  'overview.json',
  'incidents.json',
  'detections.json',
  'hunts.json',
  'risk_model.json',
]

const missing = []
for (const name of required) {
  try {
    await access(path.join(repoFixtures, name))
  } catch {
    missing.push(name)
  }
}

if (missing.length === 0) {
  process.exit(0)
}

console.error(
  `Missing fixture files next to the frontend: ${missing.join(', ')}`,
)
console.error(
  'The console imports ../fixtures. Leave the Vercel project root as the repository root so the root vercel.json can see that directory.',
)
process.exit(1)
